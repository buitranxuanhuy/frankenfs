use asupersync::Cx;
use ffs_repair::demo::{SelfHealDemoConfig, run_self_heal_demo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let result = run_self_heal_demo(&cx, &SelfHealDemoConfig::default())?;
    for line in result.output_lines {
        println!("{line}");
    }
    Ok(())
}
