"""
Kafka utilities (optional - production only)

Demo: Uses files instead of Kafka
Production: Real Kafka connections
"""

import json
from typing import List, Dict

class KafkaProducer:
    """Mock Kafka producer for demo"""
    def __init__(self, mock=True):
        self.mock = mock
    
    def send(self, topic: str, value: Dict):
        if self.mock:
            print(f"[KAFKA] → {topic}: {value.get('signal_type', 'event')}")
    
    def flush(self):
        pass
    
    def close(self):
        pass

class KafkaConsumer:
    """Mock Kafka consumer for demo"""
    def __init__(self, topics: List[str], mock=True, mock_file=None):
        self.topics = topics
        self.mock = mock
        self.mock_file = mock_file
    
    def poll(self, timeout_ms=1000):
        if self.mock and self.mock_file:
            messages = []
            with open(self.mock_file, 'r') as f:
                for line in f:
                    messages.append(json.loads(line))
            return messages
        return []
    
    def close(self):
        pass
