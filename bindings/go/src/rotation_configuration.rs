pub struct RotationConfiguration {
    pub current_public_keys: Vec<String>,
    pub next_public_keys: Vec<String>,
    pub witnesses_to_add: Vec<String>,
    pub witnesses_to_remove: Vec<String>,
    pub witness_threshold: u32,
}

impl RotationConfiguration {
    pub fn new() -> Self {
        RotationConfiguration {
            current_public_keys: vec![],
            next_public_keys: vec![],
            witnesses_to_add: vec![],
            witnesses_to_remove: vec![],
            witness_threshold: 0,
        }
    }
}

impl Default for RotationConfiguration {
    fn default() -> Self {
        Self::new()
    }
}
