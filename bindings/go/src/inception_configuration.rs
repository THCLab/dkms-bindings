pub struct InceptionConfiguration {
    pub current_public_keys: Vec<String>,
    pub next_public_keys: Vec<String>,
    pub witnesses_location: Vec<String>,
    pub witness_threshold: u32,
}

impl InceptionConfiguration {
    pub fn new() -> Self {
        InceptionConfiguration {
            current_public_keys: vec![],
            next_public_keys: vec![],
            witnesses_location: vec![],
            witness_threshold: 0,
        }
    }
}

impl Default for InceptionConfiguration {
    fn default() -> Self {
        Self::new()
    }
}
