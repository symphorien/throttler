extern crate glob;
extern crate procfs;
extern crate libc;
extern crate nix;
extern crate sysconf;
extern crate argparse;
extern crate lru_cache;
#[macro_use]
extern crate lazy_static;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::iter::FromIterator;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use glob::glob;
use libc::uid_t;
use nix::sys::signal;
use lru_cache::LruCache;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use argparse::{ArgumentParser, StoreTrue, Store};
use procfs::process::Process;

type Pid = i32;

/// ```try_or_warn!(x: Result<R, E>, format_string, format_elements, ...) -> Option<R>)```
/// This macro turns a ```Result``` ```x``` in an option like ```x.ok()``` but if ```x``` is an
/// error, an error message will be printed to stderr :
/// * the name (```ME```) of the program followed by a semicolon
/// * eprintln!(format_string, format_elements, ..., err=x.unwrap_err()) will print a custom
/// error message
/// # Example
/// ```
/// try_or_warn!(Ok(12), "Trying with {} something went bad : {err}", 12)
/// 
/// ```
/// prints nothing and yields ```Some(12)``` while
/// ```
/// try_or_warn!(Err(42), "Trying with {} something went bad : {err}", 12)
/// ```
/// yields ```None``` and prints something like 
/// ```
/// throttler : Trying with 12 something went bad : 42```
/// ```
macro_rules! try_or_warn(
    ($res:expr, $($arg:tt)*) => { {
        match $res {
            Ok(v) => Some(v),
            Err(e) => {
                eprint!("{}: ", *ME);
                eprintln!($($arg)*, err=e);
                None
            }
        }
    } }
);


/// a glob pattern for the files where temperature is available
const TEMP_SOURCES : &'static str  = "/sys/class/thermal/thermal_*/temp";


/// Reads temperature from the given file.
fn get_temp_from<P: AsRef<Path>>(file_path: P) -> Result<f32, String> {
    let mut file = File::open(file_path).map_err(|e| e.to_string())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
    let n = contents.trim().parse::<f32>().map_err(|e| e.to_string())?;
    Ok(n/1000.)
}

/// calls ```get_temp_from``` on all paths matching ```TEMP_SOURCES``` and yield their average
///
/// Error are displayed on stderr and then ignored
fn get_temp() -> Result<f32, String> {
    let mut sum = 1.;
    let mut n = 0;
    for path in glob(TEMP_SOURCES).map_err(|e| e.to_string())?.filter_map(|x| try_or_warn!(x, "Error while globbing {:?} : {err}", TEMP_SOURCES)) {
        sum += get_temp_from(path)?;
        n+=1;
    }
    Ok(sum/(n as f32))
}


/// filters out all the process we can't/should'nt slow down
///
/// Are filtered out
/// * ourselves
/// * ```init```
/// * if we are not ```root```, processes from other users (see ```man 2 kill``` for subtleties)
/// * processes owning a tty if ```OPTS.exclude_tty```
/// * processes with negative niceness
/// 
///  Returns true if the process can be slowed down
fn filter_process(process: &Process) -> bool {
    if process.pid == *SELF_PID {
        return false;
    }
    if process.pid == 1 {
        return false;
    }
    if OPTS.exclude_tty && process.stat.tty_nr != 0 && process.stat.pid == process.stat.tpgid {
        return false;
    }
    if process.stat.nice < 0 {
        return false
    }
    if *SELF_UID != 0 {
        match process.status() {
            Err(_) => return false,
            Ok(infos) => {
                if infos.suid != *SELF_UID && infos.ruid != *SELF_UID {
                    return false;
                }
            }
        }
    }
    return true
}


/// information needed to compute how much cpu a process consumes
struct CPUTime {
    /// user + system time since boot
    time: u64,
    /// timestamp when ```time``` was measured
    timestamp: Instant,
    /// cpu share computed as a result between 0 and 1
    share: f32,
    /// the name of the process because it is handy
    name: String,
}

/// global store of cpu usage mesasures
type CPUTimes = HashMap<Pid, CPUTime>;

/// Computes how much cpu time every current process took since last measures
///
/// takes two hashmaps :
/// * ```from``` which contains previous measures and will be cleared
/// * ```to``` which will store the new measures and is assumed to be initially empty
fn update_times(from: &mut CPUTimes, to: &mut CPUTimes) {
    let process_list = match try_or_warn!(procfs::process::all_processes(), "Unable to list processes: {err}") {
        None => return,
        Some(x) => x
    };
    for process in process_list.into_iter() {
        if filter_process(&process) {
                let newtime = (process.stat.utime + process.stat.stime) as u64;
                let newtimestamp = Instant::now();
                to.insert(process.pid, CPUTime {time: newtime, timestamp: newtimestamp, name: process.stat.comm, share: match from.get(&process.pid) {
                    Some(time) => (newtime - time.time) as f32 /newtimestamp.duration_since(time.timestamp).as_micros() as f32 * 1000000. / (*CLK_TCK as f32),
                    None => 0.
                }});
        }
    }
    from.clear();
}

/// kills all the pid's with the given signal.
///
/// errors will be displayed on stderr and dismissed.
fn killall<T: Iterator<Item=Pid> >(pids : T, signal : signal::Signal) {
    for pid in pids {
        try_or_warn!(signal::kill(nix::unistd::Pid::from_raw(pid), signal), "kill -{:?} {} failed : {err}", signal, pid);
    }
}

/// our signal handler : simply set ```SHOULD_EXIT``` to ```true```.
#[allow(unused_variables)]
extern "C" fn set_should_exit(signal : libc::c_int) {
    SHOULD_EXIT.store(true, Ordering::SeqCst);
}

/// where to store command line options.
///
/// for doc about the members, see ```parse_args```'s code.
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

/// return an ```Options``` accordint to given command line options
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
    /// our pid
    static ref SELF_PID : Pid = nix::unistd::getpid().as_raw();
    /// our uid
    static ref SELF_UID : uid_t = nix::unistd::getuid().as_raw();
    /// sysconf(SC_CLK_TCK)
    static ref CLK_TCK : u32 = sysconf::sysconf(sysconf::SysconfVariable::ScClkTck).expect("Unable to get sysconf(CLK_TK)") as u32;
    /// command line options
    static ref OPTS : Options = parse_args();
    /// cache of ```cached_filter_process```
    static ref FILTER_CACHE : Mutex<LruCache<Pid, bool>> = Mutex::new(LruCache::new(500));
    /// name of the current process : ```argv[0]```
    static ref ME : String = {
        match std::env::args_os().next() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => "throttler".to_owned()
        }
    };
}

/// whether we should exit as soon as possible (but when all processes are ```SIGCONT```ed
static SHOULD_EXIT : AtomicBool = AtomicBool::new(false);

fn main() {
    // here we force the lazy static to be evaluated, and thus command line options to be parsed.
    // it is needed in case of --help or --verbose : the process should exit now
    if OPTS.verbose {
        println!("Started with options : {:?}", *OPTS);
    }

    // install the signal handler
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

    let num_cpu = try_or_warn!(procfs::CpuInfo::new(), "Could not determine the number of cores: {err}").map(|i| i.num_cores()).unwrap_or(1);

    // all calculations are done in aggregated cpu time, from 0 to num_cpu, but options are from 0 to 1
    // minimum cpu usage
    let min_cpu = OPTS.min_cpu * (num_cpu as f32);
    // our two cpu usage hashmap
    let mut procinfo = HashMap::new();
    let mut reserve = HashMap::new();
    // sum of all cpu usage of the processes in time_consumers
    let mut total_cpu : f32;
    // fraction of cpu time that can be used, less than the number of cpus means slowdown
    let mut max_cpu : f32 = num_cpu as _;
    // processes matching the filter and with non negligible cpu_time
    let mut time_consumers : Vec<(f32, Pid)> = vec![];
    // those we will slow down
    let mut targets = HashSet::new();
    // timestamp for procinfo refreshes
    let mut last_times_refresh = Instant::now();
    let times_refresh_interval = Duration::from_millis((OPTS.tick*(OPTS.interval as u16)) as _);
    update_times(&mut reserve, &mut procinfo);

    let tick = Duration::from_millis(OPTS.tick as _);
    let mut last_loop = Instant::now();

    loop {
        let elapsed = Instant::now().duration_since(last_loop);
        if let Some(duration) = tick.checked_sub(elapsed) {
            std::thread::sleep(duration);
        }
        last_loop = Instant::now();

        // every second or so, recompute which processes are worth slowing down
        if last_loop.duration_since(last_times_refresh) > times_refresh_interval {
            last_times_refresh = last_loop;

            // temperature
            if let Ok(temp) = get_temp() {
                if OPTS.verbose {
                    println!("{} °C", temp);
                }
                max_cpu = min_cpu + ((num_cpu as f32) - min_cpu)*(1f32.min(0f32.max((OPTS.max_temp - temp)/(OPTS.max_temp - OPTS.min_temp))));
            }

            // processes
            std::mem::swap(&mut reserve, &mut procinfo);
            update_times(&mut reserve, &mut procinfo);
            time_consumers.extend(procinfo.iter().filter_map(|(&pid, time)| if time.share > min_cpu*OPTS.tolerance { Some((time.share, pid)) } else { None }));
            time_consumers.sort_by(|&(t, _), &(u, _)| u.partial_cmp(&t).unwrap());

            total_cpu = time_consumers.iter().fold(0., |acc, &(t, _)| acc+t);

            if OPTS.verbose {
                println!("CPU : {:0.2} %\tmax : {:0.2} %", total_cpu*100., max_cpu*100.);
                if !time_consumers.is_empty() {
                    println!("{} processes are potential targets: ", time_consumers.len());
                    for &(t, pid) in &time_consumers {
                        println!("\t{}\t{:0.2} %\t{}", pid, t*100., procinfo.get(&pid).unwrap().name);
                    }
                }
            }


            if max_cpu < (num_cpu as f32) && total_cpu * OPTS.tolerance > max_cpu {
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

            if max_cpu < (num_cpu as f32) && OPTS.verbose {
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

        // slow down selected processes
        if targets.len() > 0 && max_cpu < (num_cpu as f32) {
            killall(targets.iter().cloned(), signal::SIGSTOP);
            std::thread::sleep(std::time::Duration::from_nanos(((tick.as_nanos() as f32)*(num_cpu as f32 - max_cpu)/(num_cpu as f32)) as _));
            killall(targets.iter().cloned(), signal::SIGCONT);
        }

        // at this point, all the processes are SIGCONT'ed :
        if SHOULD_EXIT.load(Ordering::SeqCst) {
            if OPTS.verbose { println!("Exit cleanly."); }
            break;
        }

    }
}
