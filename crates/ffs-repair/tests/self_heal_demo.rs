use asupersync::Cx;
use ffs_repair::demo::{SelfHealDemoConfig, run_self_heal_demo};

#[test]
fn self_heal_demo_repairs_and_verifies_all_payloads() {
    let cx = Cx::for_testing();
    let result = run_self_heal_demo(&cx, &SelfHealDemoConfig::default())
        .expect("self_heal_demo should repair corrupted blocks");

    assert!(result.all_ok);
    assert_eq!(result.files_verified, 10);
    assert_eq!(result.corrupted_blocks, result.repaired_blocks);
}
