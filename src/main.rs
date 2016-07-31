extern crate procure;
extern crate glob;
extern crate procinfo;
extern crate time;
extern crate libc;
extern crate nix;
extern crate sysconf;
extern crate argparse;
extern crate lru_cache;
#[macro_use]
extern crate lazy_static;

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::iter::FromIterator;
use std::collections::{HashMap, HashSet};
use time::{Duration, PreciseTime};
use glob::glob;
use libc::{clock_t,pid_t,uid_t};
use nix::sys::signal;
use lru_cache::LruCache;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering, ATOMIC_BOOL_INIT};
use argparse::{ArgumentParser, StoreTrue, Store};


macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        writeln!(&mut ::std::io::stderr(), $($arg)*).expect("Failed to write to stderr");
    } }
);

macro_rules! print_stderr(
    ($($arg:tt)*) => { {
        write!(&mut ::std::io::stderr(), $($arg)*).expect("Failed to write to stderr");
    } }
);

macro_rules! try_or_warn(
    ($res:expr, $($arg:tt)*) => { {
        match $res {
            Ok(v) => Some(v),
            Err(e) => {
                print_stderr!("{}: ", *ME);
                println_stderr!($($arg)*, err=e);
                None
            }
        }
    } }
);


const TEMP_SOURCES : &'static str  = "/sys/class/thermal/thermal_*/temp";


fn get_temp_from<P: AsRef<Path>>(file_path: P) -> Result<f32, String> {
    let mut file = try!(File::open(file_path).map_err(|e| e.to_string()));
    let mut contents = String::new();
    try!(file.read_to_string(&mut contents).map_err(|e| e.to_string()));
    let n = try!(contents.trim().parse::<f32>().map_err(|e| e.to_string()));
    Ok(n/1000.)
}

fn get_temp() -> Result<f32, String> {
    let mut sum = 1.;
    let mut n = 0;
    for path in try!(glob(TEMP_SOURCES).map_err(|e| e.to_string())).filter_map(|x| try_or_warn!(x, "Error while globbing {:?} : {err}", TEMP_SOURCES)) {
        sum += try!(get_temp_from(path));
        n+=1;
    }
    Ok(sum/(n as f32))
}


fn cached_filter_process(pid : pid_t) -> std::io::Result<Option<procinfo::pid::Stat>> {
    match FILTER_CACHE.try_lock() {
        Ok(mut cache) => match cache.get_mut(&pid).map(|&mut b| b) { 
            Some(res) => match res {
                false => Ok(None),
                true => procinfo::pid::stat(pid).map(Some)
            },
            None => cacheable_filter_process(pid).map(|res| {cache.insert(pid, res.is_some()); res})
        },
        Err(_) => cacheable_filter_process(pid)
    }
}

fn cacheable_filter_process(pid: pid_t) -> std::io::Result<Option<procinfo::pid::Stat>> {
    if pid == *SELF_PID {
        return Ok(None);
    }
    if pid == 1 {
        return Ok(None);
    }
    if *SELF_UID != 0 {
        let infos = try!(procinfo::pid::status(pid));
        if infos.uid_saved != *SELF_UID && infos.uid_real != *SELF_UID {
            return Ok(None);
        }
    }
    let p = try!(procinfo::pid::stat(pid));
    if OPTS.exclude_tty && p.tty_nr != 0 && p.pid == p.tty_pgrp {
        return Ok(None);
    }
    Ok(Some(p))
}

fn filter_process(p : &procinfo::pid::Stat) -> bool {
    p.nice >= 0
}

struct CPUTime {
    time: clock_t,
    timestamp: PreciseTime,
    share: f32,
    name: String,
}

type CPUTimes = HashMap<pid_t, CPUTime>;

fn update_times(from: &mut CPUTimes, to: &mut CPUTimes) {
    for pid in procure::process::pids(){
        if let Some(Some(infos)) = try_or_warn!(cached_filter_process(pid), "Unable to parse infos for pid {} : {err}", pid) {
            if filter_process(&infos) {
                let newtime = infos.utime + infos.stime;
                let newtimestamp = PreciseTime::now();
                to.insert(pid, CPUTime {time: newtime, timestamp: newtimestamp, name: infos.command, share: match from.get(&pid) {
                    Some(time) => (newtime - time.time) as f32 /time.timestamp.to(newtimestamp).num_microseconds().unwrap() as f32 * 1000000. / (*CLK_TCK as f32),
                    None => 0.
                }});
            }
        }
    }
    from.clear();
}

fn killall<'a, T: Iterator<Item=&'a pid_t> >(pids : T, signal : signal::SigNum) {
    for &pid in pids {
        try_or_warn!(signal::kill(pid, signal), "kill -{} {} failed : {err}", signal, pid);
    }
}

#[allow(unused_variables)]
extern "C" fn set_should_exit(signal : signal::SigNum) {
    SHOULD_EXIT.store(true, Ordering::SeqCst);
}

#[derive(Debug)]
struct Options {
    min_cpu : f32,
    tolerance : f32,
    min_temp : f32,
    max_temp : f32,
    verbose : bool,
    tick: u16,
    interval: u8,
    exclude_tty: bool,
}

fn parse_args() -> Options {
    let mut opt = Options {
        min_cpu : 0.01,
        tolerance : 0.8,
        min_temp : 30.,
        max_temp : 65.,
        verbose : false,
        tick : 100,
        interval : 10,
        exclude_tty: false,
    };
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Throttles cpu usage of this user's processes when temperature rises.\n\n
                           The maximal cpu usage decreases linearly from 1 (100%) at MIN_TEMP to MIN_CPU at MAX_TEMP.\n
                           Temperatures should be given in °C and cpu usage as a float between 0 and 1.\n
                           The number of cores available is currently not taken into account.");
        ap.refer(&mut opt.verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
            "Be verbose");
        ap.refer(&mut opt.min_cpu)
            .add_option(&["-m", "--min-cpu"], Store,
            "The minimal cpu usage left to processes when temperature is above MAX_TEMP. Defaults to 0.01");
        ap.refer(&mut opt.min_temp)
            .add_option(&["-t", "--min-temp"], Store,
            "Temperature below which no contention is enforced. Defaults to 30 °C");
        ap.refer(&mut opt.max_temp)
            .add_option(&["-T", "--max-temp"], Store,
            "Temperature above which processes may use no more as MAX_CPU. Defaults to 65 °C");
        ap.refer(&mut opt.tick)
            .add_option(&["-w", "--tick"], Store,
            "Frequency of suspend/resume cycles in milliseconds. Defaults to 100.");
        ap.refer(&mut opt.interval)
            .add_option(&["-i", "--refresh-interval"], Store,
            "number of TICKS to wait before reparsing /proc for cpu usage information. Performance sensitive. Defaults to 10.");
        ap.refer(&mut opt.exclude_tty)
            .add_option(&["-x", "--exclude-tty"], StoreTrue,
            "Don't suspend processes controlling a [pt]ty.");
        ap.add_option(&["-V", "--version"],
            argparse::Print(env!("CARGO_PKG_VERSION").to_string()), "Show version and exit");
        ap.parse_args_or_exit();
    }
    opt
}


lazy_static!{
    static ref SELF_PID : pid_t = nix::unistd::getpid();
    static ref SELF_UID : uid_t = nix::unistd::getuid();
    static ref CLK_TCK : u32 = sysconf::sysconf(sysconf::SysconfVariable::ScClkTck).expect("Unable to get sysconf(CLK_TK)") as u32;
    static ref OPTS : Options = parse_args();
    static ref FILTER_CACHE : Mutex<LruCache<pid_t, bool>> = Mutex::new(LruCache::new(500));
    static ref ME : String = {
        match std::env::args_os().next() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => "throttler".to_owned()
        }
    };
}
static SHOULD_EXIT : AtomicBool = ATOMIC_BOOL_INIT;

fn main() {
    if OPTS.verbose {
        println!("Started with options : {:?}", *OPTS);
    }

    let sig_action = signal::SigAction::new(signal::SigHandler::Handler(set_should_exit), signal::SaFlags::empty(), signal::SigSet::all());
    
    unsafe {
        for &signal in [
            signal::SIGHUP,
            signal::SIGINT,
            signal::SIGQUIT,
            signal::SIGTERM,
            ].iter() {
                signal::sigaction(signal, &sig_action).expect("Could not set signal handler");
        }
    }

    let mut procinfo = HashMap::new();
    let mut reserve = HashMap::new();
    let mut total_cpu : f32 = 0.;
    let mut max_cpu : f32 = 1.;
    let mut time_consumers : Vec<(f32, pid_t)> = vec![];
    let mut targets = HashSet::new();
    let mut last_times_refresh = PreciseTime::now();
    let times_refresh_interval = Duration::milliseconds((OPTS.tick*(OPTS.interval as u16)) as i64);
    update_times(&mut reserve, &mut procinfo);

    let tick = Duration::milliseconds(OPTS.tick as i64);
    let mut last_loop = PreciseTime::now();

    loop {
        if let Ok(duration) = (tick - last_loop.to(PreciseTime::now())).to_std() {
            std::thread::sleep(duration);
        }
        last_loop = PreciseTime::now();

        // une fois par seconde, calculer les pids à relentir et la bride
        if last_times_refresh.to(PreciseTime::now()) > times_refresh_interval {
            last_times_refresh = PreciseTime::now();

            // temperature
            if let Ok(temp) = get_temp() {
                if OPTS.verbose {
                    println!("{} °C", temp);
                }
                max_cpu = OPTS.min_cpu + (1. - OPTS.min_cpu)*1f32.min(0f32.max((OPTS.max_temp - temp)/(OPTS.max_temp - OPTS.min_temp)));
            }

            // processes
            std::mem::swap(&mut reserve, &mut procinfo);
            update_times(&mut reserve, &mut procinfo);
            time_consumers.extend(procinfo.iter().filter_map(|(&pid, time)| if time.share > OPTS.min_cpu*OPTS.tolerance { Some((time.share, pid)) } else { None }));
            time_consumers.sort_by(|&(t, _), &(u, _)| u.partial_cmp(&t).unwrap());

            total_cpu = time_consumers.iter().fold(0., |acc, &(t, _)| acc+t);

            if OPTS.verbose {
                println!("CPU : {} %\tmax : {} %", (total_cpu*100.) as u8, (max_cpu*100.) as u8);
                for &(t, pid) in &time_consumers {
                    println!("\t{}\t{}\t{}", pid, (t*100.) as u8, procinfo.get(&pid).unwrap().name);
                }
            }


            if max_cpu < 1. && total_cpu * OPTS.tolerance > max_cpu {
                let mut partial_sum = 0.;
                for &(t, pid) in &time_consumers {
                    partial_sum += t;
                    targets.insert(pid);
                    if partial_sum >= total_cpu * OPTS.tolerance {
                        break;
                    }
                }
            }
            
            targets = &targets & &HashSet::from_iter(&mut time_consumers.drain(..).map(|(_, pid)| pid));

            if max_cpu < 1. && OPTS.verbose {
                println!("Enforcing threshold on");
                for pid in targets.iter() {
                    println!("\t{}\t{}", pid, procinfo.get(&pid).unwrap().name);
                }
            }
            
            // at this point, all the processes are SIGCONT'ed :
            if SHOULD_EXIT.load(Ordering::SeqCst) {
                if OPTS.verbose { println!("Exit cleanly."); }
                break;
            }
        }

        // ralentir les pids sélectionnés
        if targets.len() > 0 && max_cpu < 1. {
            killall(targets.iter(), signal::SIGSTOP);
            std::thread::sleep(std::time::Duration::new(0, ((tick.num_nanoseconds().unwrap() as f32)*(1.-max_cpu)) as u32));
            killall(targets.iter(), signal::SIGCONT);
        }

        // at this point, all the processes are SIGCONT'ed :
        if SHOULD_EXIT.load(Ordering::SeqCst) {
            if OPTS.verbose { println!("Exit cleanly."); }
            break;
        }

    }
}
