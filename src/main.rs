use std::env;
use std::collections::HashMap;
use std::str::FromStr;
use regex::Regex;
use std::fmt;
use std::error::Error;
use std::str;

use log::debug;

#[allow(dead_code)]
#[cfg(not(test))]
#[allow(unused_imports)]
use log::{error, info, warn}; // Use log crate when building application

#[allow(dead_code)]
#[allow(unused_imports)]
#[cfg(test)]
use std::{println as info, println as warn, println as error}; // Workaround to use prinltn! for logs.

use lazy_static::lazy_static;

lazy_static! {
    static ref RE_CONTEXT : Regex = Regex::new(r#"^(\d+)\s+([.0-9]+)\s+([_a-z]+)(\(.*)$"#).expect("failed to compile regex for context");
    static ref RE_CONTEXT_RESUMED : Regex = Regex::new(r#"^(\d+)\s+([.0-9]+)\s+<\.\.\. ([^<>]+)>(.*)$"#).expect("failed to compile regex for resumed context");

    static ref RE_CLONE : Regex = Regex::new(r#"^.+[^\d](\d+)$"#).expect("failed to compile regex for clone");

    static ref RE_EXEC : Regex = Regex::new(r#"^\("([^"]+)", \[([^\[]+)\],"#).expect("failed to compile regex for exec");
    static ref RE_EXIT : Regex = Regex::new(r#"^(\d+)\s+([.\d]+)\s+([_a-z]+)\("#).expect("failed to compile regex for exit_group");
}

type MyResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct ForkTree {
    root: ForkProcess,
    processes: HashMap<u64, ForkProcess>,
}

#[derive(Debug)]
struct ForkProcess {
    cmd: String,
    pid: u64,
    duration: f64,
    start_time: f64,
    ppid: Option<u64>,
    args: Vec<String>,
    cpids: Vec<u64>,
}

#[derive(Debug)]
struct Context {
    syscall: Syscall,
    pid: u64,
    timestamp: f64,
    remaining_msg: String,
}

#[derive(Debug)]
enum MyError {
    InvalidLine,
    InvalidProcess
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for MyError {}

#[derive(Debug)]
enum Syscall {
    Clone,
    Exec,
    Exit,
    CloneResumed,
    ExecResumed,
}

impl FromStr for Syscall {

    type Err = ();

    fn from_str(input: &str) -> Result<Syscall, Self::Err> {
        match input {
            "clone"  => Ok(Syscall::Clone),
            "execve"  => Ok(Syscall::Exec),
            "clone resumed"  => Ok(Syscall::CloneResumed),
            "execve resumed"  => Ok(Syscall::ExecResumed),
            "exit_group" => Ok(Syscall::Exit),
            _      => Err(()),
        }
    }
}


impl ForkTree {
    fn new() -> ForkTree {
        ForkTree{
            root: ForkProcess::new(),
            processes: HashMap::new(),
        }
    }

    fn get_process(&self, pid: &u64) -> Option<&ForkProcess> {
        self.processes.get(pid)
    }

    fn get_process_mut(&mut self, pid: &u64) -> Option<&mut ForkProcess> {
        self.processes.get_mut(pid)
    }

    fn process_line(&mut self, line: &str) -> MyResult<()> {

        match ForkTree::parse_context(line) {
            None => {
                // debug!("Ignored invalid line: {}", &line);
            },
            Some(context) => {
                debug!("Got context: {:?}", &context);

                match context.syscall {
                    Syscall::Clone | Syscall::CloneResumed => {
                        self.process_clone_line(&context)?;
                    },
                    Syscall::Exec => {
                        self.process_exec_line(&context)?;
                    },
                    Syscall::Exit => {
                        self.process_exit_line(&context)?;
                    },
                    _ => {
                        debug!("XXX {}", &line);
                    }
                }
            },
        }

        Ok(())
    }

    fn parse_context(line: &str) -> Option<Context> {
        let mut caps = RE_CONTEXT.captures(line);

        if caps.is_none() {
            caps = RE_CONTEXT_RESUMED.captures(line);
        }

        let caps = caps?;

        let pid_str = caps.get(1)?.as_str();
        let pid = pid_str.parse::<u64>().ok()?;

        let timestamp_str = caps.get(2)?.as_str();
        let timestamp = timestamp_str.parse::<f64>().ok()?;

        let syscall_str = caps.get(3)?.as_str();
        let syscall = Syscall::from_str(syscall_str).ok()?;

        let remaining_str = caps.get(4)?.as_str();

        Some(Context{
            syscall,
            pid,
            timestamp,
            remaining_msg: remaining_str.to_string(),
        })
    }

    fn process_clone_line(&mut self, ctxt: &Context) -> MyResult<()> {
        let line = &ctxt.remaining_msg;

        debug!("Processing clone line: {}", &line);

        match RE_CLONE.captures(line) {
            None => {
                error!("Invalid clone line: {}", &line);
            },
            Some(caps) => {
                let child_pid_str = caps.get(1).expect("should get the clone child process").as_str();
                let child_pid = child_pid_str.parse::<u64>()?;

                self.processes.entry(child_pid).or_insert(ForkProcess::new_with_ppid(child_pid, ctxt.pid));
                (*self.processes.entry(ctxt.pid).or_insert(ForkProcess::new_with_pid(ctxt.pid))).add_child_process(child_pid);
            }
        }
        Ok(())
    }

    fn process_exec_line(&mut self, ctxt: &Context) -> MyResult<()> {
        let line = &ctxt.remaining_msg;
        debug!("Processing exec line: {}", &line);

        // r#"^(\d+)\s+([.\d]+)\s+([a-z]+)\("([^"]+)", \[([^\[]+)\],"#
        let caps = RE_EXEC.captures(line).ok_or(MyError::InvalidLine)?;
        let cmd_and_args_str = caps.get(2).ok_or(MyError::InvalidLine)?.as_str();
        let mut cmd_and_args = cmd_and_args_str.split(", ");
        let cmd_str = cmd_and_args.next().ok_or(MyError::InvalidLine)?;
        let cmd : String = serde_json::from_str(cmd_str)?;

        let mut p = self.get_process_mut(&ctxt.pid).ok_or(MyError::InvalidProcess)?;
        p.cmd = cmd;

        let mut args = vec![];

        for arg_str in cmd_and_args {
            let arg : String = serde_json::from_str(arg_str)?;
            args.push(arg);
        }

        p.args = args;

        Ok(())
    }

    fn process_exit_line(&mut self, ctxt: &Context) -> MyResult<()> {
        let line = &ctxt.remaining_msg;
        debug!("Processing exit line: {}", &line);
        let mut p = self.get_process_mut(&ctxt.pid).ok_or(MyError::InvalidProcess)?;
        p.duration = ctxt.timestamp - p.start_time;
        Ok(())
    }

    fn print_fork_tree(&self, pid: u64) -> MyResult<()> {
        self._print_fork_tree(pid, 0)
    }

    fn _print_fork_tree(&self, pid: u64, indent: usize) -> MyResult<()> {
        let p = self.get_process(&pid).ok_or(MyError::InvalidProcess)?;

        if p.cmd != "" && p.cmd != "/bin/sh" && p.cmd != "sudo" {
            println!("{}{} {} - {:.1}ms", "    ".repeat(indent), p.cmd, p.args.join(" "), p.duration * 1000.0);
        }

        for cpid in p.cpids.iter() {
            if p.cmd != "/bin/sh" && p.cmd != "sudo" {
                self._print_fork_tree(*cpid, indent + 1)?;
            } else {
                self._print_fork_tree(*cpid, indent)?;
            }
        }

        Ok(())
    }
}

impl ForkProcess {
    fn new() -> ForkProcess {
        ForkProcess{
            cmd: "".into(),
            pid: 0,
            ppid: None,
            duration: 0.0,
            start_time: 0.0,
            args: vec![],
            cpids: vec![],
        }
    }

    fn new_with_ppid(pid: u64, ppid: u64) -> ForkProcess {
        ForkProcess{
            cmd: "".into(),
            pid,
            ppid: Some(ppid),
            duration: 0.0,
            start_time: 0.0,
            args: vec![],
            cpids: vec![],
        }
    }

    fn new_with_pid(pid: u64) -> ForkProcess {
        ForkProcess{
            cmd: "".into(),
            pid,
            ppid: None,
            duration: 0.0,
            start_time: 0.0,
            args: vec![],
            cpids: vec![],
        }
    }

    fn add_child_process(&mut self, cpid: u64) {
        self.cpids.push(cpid);
    }
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }

    env_logger::init();

    let ft = ForkTree::new();
    info!("XX: {:?}", ft);
}

#[cfg(test)]
mod tests {
    use super::ForkTree;
    use super::ForkProcess;

    #[test]
    fn test_process_clone() {
        let mut ft = ForkTree::new();
        let line = "14991      0.000000 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f429c104a50) = 1783473";
        ft.process_line(&line).expect("failed to process line");
        println!("XXX {:?}", &ft.processes);
        ft.get_process(&14991).expect("should found this process");
        ft.get_process(&1783473).expect("should found this process");
    }

    #[test]
    fn test_process_clone_resumed() {
        let mut ft = ForkTree::new();
        let line = "14991      0.001354 <... clone resumed>, child_tidptr=0x7f429c104a50) = 1783475";
        ft.process_line(&line).expect("failed to process line");
        ft.get_process(&14991).expect("should found this process");
        ft.get_process(&1783475).expect("should found this process");
    }

    #[test]
    fn test_process_exec() {
        let mut ft = ForkTree::new();
        let pid = 1783473;
        let p = ForkProcess::new_with_pid(pid);
        ft.processes.insert(pid, p);
        let line = r#"1783473      0.009736 execve("/bin/sh", ["/bin/sh", "-c", "mkdir -p /home/pi/ovpns"], ["SHELL=/bin/bash", "PWD=/home/pi/firewalla/api", "LOGNAME=pi", "HOME=/home/pi", "LANG=C.UTF-8", "ZEEK_DEFAULT_LISTEN_ADDRESS=127.0.0.1", "INVOCATION_ID=72f5168e3b0c47b5bbad82fa8859698b", "FIREWALLA_PLATFORM=gold", "USER=pi", "SHLVL=2", "JOURNAL_STREAM=9:147781", "UV_THREADPOOL_SIZE=16", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "OLDPWD=/home/pi/firewalla/api", "_=/home/pi/.nvm/versions/node/v12.14.0/bin/node"]) = 0"#;
        ft.process_line(&line).expect("failed to process line");
        let p = ft.get_process(&1783473).expect("should found this process");
        assert_eq!(p.cmd, "/bin/sh".to_string());
        assert_eq!(p.args, vec!["-c".to_string(), "mkdir -p /home/pi/ovpns".to_string()]);
    }

    #[test]
    fn test_process_exit() {
        let mut ft = ForkTree::new();
        let pid = 1783473;
        let p = ForkProcess::new_with_pid(pid);
        ft.processes.insert(pid, p);
        let line = r#"1783473      0.000177 exit_group(0)     = ?"#;
        ft.process_line(&line).expect("failed to process line");
        let p = ft.get_process(&1783473).expect("should found this process");
        assert_eq!(p.start_time, 0.0);
        assert_eq!(p.duration, 0.000177);
    }

    #[test]
    fn test_sample_file() {
        // let sample_file = include_str!("sample.output");
        // let mut ft = ForkTree::new();
        // for line in sample_file.split("\n") {
        //     ft.process_line(&line);
        // }

        // for (pid, p) in ft.processes.iter() {
        //     if p.cmd != "" {
        //         println!("XXX - {:?}", p);
        //     }
        // }

        // assert!(false);
    }

    #[test]
    fn test_print_tree() {
        let sample_file = include_str!("sample.output");
        let mut ft = ForkTree::new();
        for line in sample_file.split("\n") {
            ft.process_line(&line);
        }

        ft.print_fork_tree(14991);

        assert!(false);
    }
}
