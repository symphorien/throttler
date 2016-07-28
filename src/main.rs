extern crate procure;
extern crate glob;
extern crate procinfo;
extern crate time;
extern crate libc;
extern crate nix;
extern crate sysconf;
#[macro_use]
extern crate lazy_static;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::iter::FromIterator;
use std::collections::{HashMap, HashSet};
use time::{Duration, PreciseTime};
use glob::glob;
use libc::{clock_t,pid_t,uid_t};
use nix::sys::signal;
use std::sync::atomic::{AtomicBool, Ordering, ATOMIC_BOOL_INIT};

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
    for path in try!(glob("/sys/class/thermal/thermal_*/temp").map_err(|e| e.to_string())).filter_map(|globresult| match globresult { Ok(path) => Some(path), Err(_) => None }) {
        sum += try!(get_temp_from(path));
        n+=1;
    }
    Ok(sum/(n as f32))
}

fn filter_process(p : &procinfo::pid::Stat) -> bool {
    if p.pid == *SELF_PID {
        return false;
    }
    if p.priority < 20 { // nice <0 or realtime
        return false;
    }
    if p.pid == 1 {
        return false;
    }
    if *SELF_UID != 0 {
        match procinfo::pid::status(p.pid) {
            Ok(infos)=> {
                //println!("oui{}", p.command);
                if infos.uid_saved != *SELF_UID && infos.uid_real != *SELF_UID {
                    return false;
                }
            },
            Err(e) => {
                println!("Unable to get status of {} ({}) : {:?}", p.command, p.pid, e);
                //unsafe{libc::system(format!("cat /proc/{}/status", p.pid).as_ptr() as *const i8)};
                ()
            }
        }
    }
    true
}

struct CPUTime {
    time: clock_t,
    timestamp: PreciseTime,
    share: f32,
    name: String,
}

type CPUTimes = HashMap<pid_t, CPUTime>;

fn update_times(from: &mut CPUTimes, to: &mut CPUTimes) -> Result<(), String> {
    for pid in procure::process::pids(){
        let infos = try!(procinfo::pid::stat(pid).map_err(|e| e.to_string()));
        if filter_process(&infos) {
            let newtime = infos.utime + infos.stime;
            let newtimestamp = PreciseTime::now();
            to.insert(pid, CPUTime {time: newtime, timestamp: newtimestamp, name: infos.command, share: match from.get(&pid) {
                Some(time) => (newtime - time.time) as f32 /time.timestamp.to(newtimestamp).num_microseconds().unwrap() as f32 * 1000000. / (*CLK_TCK as f32),
                None => 0.
            }});
        }
    }
    from.clear();
    Ok(())
}

fn killall<'a, T: Iterator<Item=&'a pid_t> >(pids : T, signal : signal::SigNum) {
    for &pid in pids {
        if let Err(e) = signal::kill(pid, signal) {
            println!("Error killing {} with {} : {}", pid, signal, e);
        }
    }
}

#[allow(unused_variables)]
extern "C" fn set_should_exit(signal : signal::SigNum) {
    SHOULD_EXIT.store(true, Ordering::SeqCst);
}


lazy_static!{
    static ref SELF_PID : pid_t = nix::unistd::getpid();
    static ref SELF_UID : uid_t = nix::unistd::getuid();
    static ref CLK_TCK : u32 = sysconf::sysconf(sysconf::SysconfVariable::ScClkTck).expect("Unable to get sysconf(CLK_TK)") as u32;
}
static SHOULD_EXIT : AtomicBool = ATOMIC_BOOL_INIT;

const MIN_CPU : f32 = 0.01;
const TOLERANCE : f32 = 0.8;
const MIN_TEMP : f32 = 50.;
const MAX_TEMP : f32 = 65.;

fn main() {

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
    let mut time_consumers : Vec<(f32, pid_t, String)> = vec![];
    let mut targets = HashSet::new();
    let mut last_times_refresh = PreciseTime::now();
    let times_refresh_interval = Duration::seconds(2);
    if let Err(e) = update_times(&mut reserve, &mut procinfo) {
        println!("{}", e);
    }

    let tick = Duration::milliseconds(100);
    let mut last_loop = PreciseTime::now();

    loop {
        if let Ok(duration) = (tick - last_loop.to(PreciseTime::now())).to_std() {
            std::thread::sleep(duration);
        }
        last_loop = PreciseTime::now();

        // une fois par seconde, calculer les pids à relentir et la bride
        if last_times_refresh.to(PreciseTime::now()) > times_refresh_interval {
            last_times_refresh = PreciseTime::now();
            std::mem::swap(&mut reserve, &mut procinfo);
            if let Err(e) = update_times(&mut reserve, &mut procinfo) {
                println!("{}", e);
            }
            time_consumers.extend(procinfo.iter().filter_map(|(&pid, time)| if time.share > MIN_CPU*TOLERANCE { Some((time.share, pid, time.name.to_owned())) } else { None }));
            time_consumers.sort_by(|&(t, _, _), &(u, _, _)| u.partial_cmp(&t).unwrap());

            total_cpu = time_consumers.iter().fold(0., |acc, &(t, _, _)| acc+t);
            println!("CPU : {} % : {:?}", total_cpu, time_consumers);

            if total_cpu * TOLERANCE > max_cpu {
                let mut partial_sum = 0.;
                for &(t, pid, _) in &time_consumers {
                    partial_sum += t;
                    targets.insert(pid);
                    if partial_sum >= total_cpu * TOLERANCE {
                        break;
                    }
                }
            }
            
            targets = &targets & &HashSet::from_iter(&mut time_consumers.drain(..).map(|(_, pid, _)| pid));


            if let Ok(temp) = get_temp() {
                println!("{} °C", temp);
                max_cpu = MIN_CPU + (1. - MIN_CPU)*1f32.min(0f32.max((MAX_TEMP - temp)/(MAX_TEMP - MIN_TEMP)));
            }
            println!("Target {} % -> ralentissation\nenforced on {:?}", max_cpu, targets);
            
            // at this point, all the processes are SIGCONT'ed :
            if SHOULD_EXIT.load(Ordering::SeqCst) {
                println!("Exit cleanly.");
                break;
            }
        }

        // ralentir les pids sélectionnés
        if targets.len() > 0 && total_cpu * TOLERANCE > max_cpu {
            killall(targets.iter(), signal::SIGSTOP);
            std::thread::sleep(std::time::Duration::new(0, ((tick.num_nanoseconds().unwrap() as f32)*(1.-max_cpu)) as u32));
            killall(targets.iter(), signal::SIGCONT);
        }

        // at this point, all the processes are SIGCONT'ed :
        if SHOULD_EXIT.load(Ordering::SeqCst) {
            println!("Exit cleanly.");
            break;
        }

    }
}
