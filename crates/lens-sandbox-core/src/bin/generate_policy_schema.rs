fn main() {
    let schema = lens_sandbox_core::policy_schema::generate_json_schema();
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
