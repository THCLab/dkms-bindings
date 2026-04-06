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

    pub fn with_current_keys(&mut self, keys: Vec<String>) -> &mut Self {
        self.current_public_keys = keys;
        self
    }

    pub fn with_next_keys(&mut self, keys: Vec<String>) -> &mut Self {
        self.next_public_keys = keys;
        self
    }

    pub fn with_witnesses(&mut self, locations: Vec<String>) -> &mut Self {
        self.witnesses_location = locations;
        self
    }

    pub fn with_witness_threshold(&mut self, threshold: u32) -> &mut Self {
        self.witness_threshold = threshold;
        self
    }
}

impl Default for InceptionConfiguration {
    fn default() -> Self {
        Self::new()
    }
}
