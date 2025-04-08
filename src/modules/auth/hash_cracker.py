"""
Hash Cracker Module for APT Toolkit

Features:
- Multiple hash algorithm support
- Dictionary attacks
- Brute force attacks
- Rainbow table support
- Performance optimization
- Thread-safe operation

WARNING: This module should only be used on hashes you own or have explicit permission to crack.
Unauthorized hash cracking may be illegal in some jurisdictions.
"""

import time
import threading
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from enum import Enum, auto

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.crypto import CryptoHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event
from src.utils.helpers import ErrorHelpers

logger = get_logger(__name__)

class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    SHA512 = auto()
    NTLM = auto()
    BCRYPT = auto()

class AttackMode(Enum):
    """Attack modes"""
    DICTIONARY = auto()
    BRUTEFORCE = auto()
    RAINBOW = auto()

class HashCracker(ScanModule):
    """Hash cracking module"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "hash_cracker"
        self.max_threads = config.auth.max_threads
        self._stop_event = threading.Event()
        
    def initialize(self) -> None:
        """Initialize cracker resources"""
        logger.info(f"Initialized {self.module_name} with {self.max_threads} threads")
        
    def cleanup(self) -> None:
        """Cleanup cracker resources"""
        self._stop_event.set()
        logger.info(f"Cleaned up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for hash cracking"""
        if not target.metadata.get("hashes"):
            return False
        return True
        
    def _hash_match(self, algorithm: HashAlgorithm, plaintext: str, target_hash: str) -> bool:
        """Check if plaintext matches target hash"""
        try:
            if algorithm == HashAlgorithm.MD5:
                return hashlib.md5(plaintext.encode()).hexdigest() == target_hash
            elif algorithm == HashAlgorithm.SHA1:
                return hashlib.sha1(plaintext.encode()).hexdigest() == target_hash
            elif algorithm == HashAlgorithm.SHA256:
                return hashlib.sha256(plaintext.encode()).hexdigest() == target_hash
            elif algorithm == HashAlgorithm.SHA512:
                return hashlib.sha512(plaintext.encode()).hexdigest() == target_hash
            elif algorithm == HashAlgorithm.NTLM:
                return CryptoHelpers.ntlm_hash(plaintext) == target_hash
            # bcrypt would require special handling
            return False
        except Exception:
            return False
            
    def _dictionary_attack(self, algorithm: HashAlgorithm, target_hash: str, wordlist: List[str]) -> Optional[str]:
        """Perform dictionary attack on hash"""
        for word in wordlist:
            if self._stop_event.is_set():
                return None
                
            if self._hash_match(algorithm, word, target_hash):
                return word
        return None
        
    def _bruteforce_attack(self, algorithm: HashAlgorithm, target_hash: str, charset: str, max_length: int) -> Optional[str]:
        """Perform brute force attack on hash"""
        from itertools import product
        
        for length in range(1, max_length + 1):
            if self._stop_event.is_set():
                return None
                
            for attempt in product(charset, repeat=length):
                plaintext = ''.join(attempt)
                if self._hash_match(algorithm, plaintext, target_hash):
                    return plaintext
        return None
        
    def _crack_hash(self, algorithm: HashAlgorithm, target_hash: str, attack_mode: AttackMode, 
                   wordlist: Optional[List[str]] = None, 
                   charset: Optional[str] = None,
                   max_length: Optional[int] = 8) -> Dict[str, Any]:
        """Attempt to crack a single hash"""
        result = {
            "hash": target_hash,
            "algorithm": algorithm.name,
            "cracked": False,
            "plaintext": None,
            "mode": attack_mode.name,
            "time_taken": 0
        }
        
        start_time = time.time()
        
        try:
            if attack_mode == AttackMode.DICTIONARY and wordlist:
                result["plaintext"] = self._dictionary_attack(algorithm, target_hash, wordlist)
            elif attack_mode == AttackMode.BRUTEFORCE and charset and max_length:
                result["plaintext"] = self._bruteforce_attack(algorithm, target_hash, charset, max_length)
            # Rainbow table mode would be implemented here
            
            result["cracked"] = result["plaintext"] is not None
            result["time_taken"] = time.time() - start_time
            
            if result["cracked"]:
                logger.info(f"Cracked hash {target_hash} => {result['plaintext']}")
                
        except Exception as e:
            logger.error(f"Hash cracking failed: {str(e)}")
            
        return result
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Execute hash cracking against target
        
        Args:
            target: ScanTarget specifying hashes and attack parameters
            
        Returns:
            ScanResult with cracking results
        """
        if not self.validate_target(target):
            logger.error("Invalid hash cracking target")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )
            
        hashes = target.metadata.get("hashes", [])
        algorithm = HashAlgorithm[target.metadata.get("algorithm", "MD5").upper()]
        attack_mode = AttackMode[target.metadata.get("mode", "DICTIONARY").upper()]
        wordlist = target.metadata.get("wordlist", [])
        charset = target.metadata.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")
        max_length = target.metadata.get("max_length", 8)
        
        logger.info(f"Starting hash cracking on {len(hashes)} hashes using {attack_mode.name} attack")
        
        try:
            results = []
            cracked_count = 0
            self._stop_event.clear()
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                for target_hash in hashes:
                    if self._stop_event.is_set():
                        break
                        
                    futures.append(
                        executor.submit(
                            self._crack_hash,
                            algorithm,
                            target_hash,
                            attack_mode,
                            wordlist,
                            charset,
                            max_length
                        )
                    )
                    
                for future in futures:
                    if self._stop_event.is_set():
                        break
                        
                    try:
                        result = future.result()
                        results.append(result)
                        
                        if result["cracked"]:
                            cracked_count += 1
                            
                    except Exception as e:
                        logger.error(f"Hash cracking attempt failed: {str(e)}")
                        
            return ScanResult(
                target=target,
                data={
                    "cracked": cracked_count,
                    "total": len(results),
                    "results": results,
                    "stats": {
                        "success_rate": cracked_count / max(1, len(results)),
                        "average_time": sum(r["time_taken"] for r in results) / max(1, len(results)),
                        "algorithm": algorithm.name
                    }
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"Hash cracking failed: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return HashCracker()

# Example usage:
# cracker = HashCracker()
# target = ScanTarget(
#     metadata={
#         "hashes": ["5f4dcc3b5aa765d61d8327deb882cf99", "d077f..."],
#         "algorithm": "MD5",
#         "mode": "DICTIONARY",
#         "wordlist": ["password", "123456", "qwerty"]
#     }
# )
# result = cracker.execute(target)
# print(json.dumps(result.data, indent=2))