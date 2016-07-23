extern crate procure;
extern crate glob;
extern crate procinfo;
extern crate time;
extern crate libc;
extern crate nix;
extern crate sysconf;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::collections::HashMap;
use time::{Duration, PreciseTime};
use glob::glob;
use libc::{clock_t,pid_t,uid_t};
use nix::sys::signal;

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
    if p.pid == unsafe{self_pid} {
        return false;
    }
    if p.priority < 20 { // nice <0 or realtime
        return false;
    }
    if p.pid == 1 {
        return false;
    }
    if unsafe{self_uid} != 0 {
        match procinfo::pid::status(p.pid) {
            Ok(infos)=> {
                //println!("oui{}", p.command);
                if infos.uid_saved != unsafe{self_uid} && infos.uid_real != unsafe{self_uid} {
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
                Some(time) => (newtime - time.time) as f32 /time.timestamp.to(newtimestamp).num_microseconds().unwrap() as f32 * 1000000. / (unsafe{CLK_TCK} as f32),
                None => 0.
            }});
        }
    }
    from.clear();
    Ok(())
}

fn killall(pids : &Vec<(f32, pid_t, String)>, signal : signal::SigNum) {
    for &(_, pid, ref name) in pids {
        if let Err(e) = signal::kill(pid, signal) {
            println!("Error killing {} ({}) with {} : {}", name, pid, signal, e);
        }
    }
}


static mut self_pid : pid_t = 0;
static mut self_uid : uid_t = 0;
static mut CLK_TCK : u32 = 100;

const MIN_CPU : f32 = 0.01;
const MAX_CPU : f32 = 0.05;
const TOLERANCE : f32 = 0.8;

fn main() {
    
    unsafe {
        self_pid = nix::unistd::getpid();
        self_uid = nix::unistd::getuid();
        CLK_TCK = sysconf::sysconf(sysconf::SysconfVariable::ScClkTck).expect("Unable to get sysconf(CLK_TK)") as u32;
        println!("{} {} {}", self_pid, self_uid, CLK_TCK);
    }

    let mut procinfo = HashMap::new();
    let mut reserve = HashMap::new();
    let mut total_cpu : f32 = 0.;
    let mut time_consumers : Vec<(f32, pid_t, String)> = vec![];
    let mut last_times_refresh = PreciseTime::now();
    let times_refresh_interval = Duration::seconds(2);
    if let Err(e) = update_times(&mut reserve, &mut procinfo) {
        println!("{}", e);
    }

    let tick = Duration::milliseconds(100);
    let mut last_loop = PreciseTime::now();

    loop {
        if let Ok(duration) = (tick - last_loop.to(PreciseTime::now())).to_std() {
            //println!("{:?}", duration);
            std::thread::sleep(duration);
        }
        last_loop = PreciseTime::now();

        // une fois par seconde, calculer les pids à relentir
        if last_times_refresh.to(PreciseTime::now()) > times_refresh_interval {
            last_times_refresh = PreciseTime::now();
            std::mem::swap(&mut reserve, &mut procinfo);
            if let Err(e) = update_times(&mut reserve, &mut procinfo) {
                println!("{}", e);
            }
            time_consumers.clear();
            time_consumers.extend(procinfo.iter().filter_map(|(&pid, time)| if time.share > MIN_CPU { Some((time.share, pid, time.name.to_owned())) } else { None }));
            time_consumers.sort_by(|&(t, _, _), &(u, _, _)| u.partial_cmp(&t).unwrap());

            total_cpu = time_consumers.iter().fold(0., |acc, &(t, _, _)| acc+t);

            if total_cpu * TOLERANCE > MAX_CPU {
                let mut partial_sum = 0.;
                let mut i:usize = 0;
                for &(t, _, _) in &time_consumers {
                    partial_sum += t;
                    i+=1;
                    if partial_sum >= total_cpu * TOLERANCE {
                        break;
                    }
                }
                time_consumers.truncate(i);
            } else {
                time_consumers.clear();
            }

            println!("blah");
            for &(ref time, ref pid, ref name) in &time_consumers {
                println!("{}\t{}\t{}", pid, time*100., name);
                //println!("{:?}", procinfo::pid::status(pid).unwrap())
            }
        }

        // ralentir les pids sélectionnés
        if time_consumers.len() > 0 {
            killall(&time_consumers, signal::SIGSTOP);
            std::thread::sleep(std::time::Duration::new(0, ((tick.num_nanoseconds().unwrap() as f32)*(1.-MAX_CPU/total_cpu)) as u32));
            killall(&time_consumers, signal::SIGCONT);
        }
    }
}
