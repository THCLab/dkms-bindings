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

    pub fn with_current_keys(&mut self, keys: Vec<String>) -> &mut Self {
        self.current_public_keys = keys;
        self
    }

    pub fn with_next_keys(&mut self, keys: Vec<String>) -> &mut Self {
        self.next_public_keys = keys;
        self
    }

    pub fn with_witnesses_to_add(&mut self, locations: Vec<String>) -> &mut Self {
        self.witnesses_to_add = locations;
        self
    }

    pub fn with_witnesses_to_remove(&mut self, witness_ids: Vec<String>) -> &mut Self {
        self.witnesses_to_remove = witness_ids;
        self
    }

    pub fn with_witness_threshold(&mut self, threshold: u32) -> &mut Self {
        self.witness_threshold = threshold;
        self
    }
}

impl Default for RotationConfiguration {
    fn default() -> Self {
        Self::new()
    }
}
