use ffs_mvcc::demo::run_snapshot_isolation_demo;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run_snapshot_isolation_demo() {
        Ok(result) => {
            for line in result.output_lines() {
                println!("{line}");
            }
            if result.isolated {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("mvcc_demo failed: {error}");
            ExitCode::FAILURE
        }
    }
}
