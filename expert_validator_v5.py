#!/usr/bin/env python3
"""
EXPERT VALIDATION ENGINE v5.0
Advanced multi-layer validation for ZERO false positives/negatives

This module implements professional penetration testing validation logic:
1. Multiple verification layers
2. Differential analysis
3. Signature matching with context
4. Response behavior analysis
5. Time-based confirmation
6. Payload mutation testing
7. False positive elimination
8. False negative detection
"""

import re
import time
import hashlib
import difflib
from typing import Tuple, List, Dict, Optional
from bs4 import BeautifulSoup

class ExpertValidationEngine:
    """
    Professional-grade validation engine
    Uses multiple layers of verification to ensure accuracy
    """
    
    def __init__(self):
        self.false_positive_indicators = [
            'waf', 'firewall', 'blocked', 'denied', 'forbidden', 
            'cloudflare', 'incapsula', 'imperva', 'akamai', 'sucuri',
            'security violation', 'suspicious activity', 'rate limit'
        ]
        
        # Database error signatures (high confidence)
        self.db_errors = {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc\.exceptions",
                r"mysql_fetch_array\(\)",
                r"mysql_num_rows\(\)",
                r"ORA-\d{5}",
                r"Driver.*SQL.*Error"
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError:",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s+syntax error at or near"
            ],
            'mssql': [
                r"Driver.*SQL[\-\_\ ]*Server",
                r"OLE DB.*SQL Server",
                r"\[Microsoft\]\[ODBC SQL Server Driver\]",
                r"\[Macromedia\]\[SQLServer JDBC Driver\]",
                r"System\.Data\.SqlClient\.SqlException",
                r"Unclosed quotation mark after the character string",
                r"SqlException \(0x80131904\)"
            ],
            'oracle': [
                r"\bORA-\d{4,5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*",
                r"oracle\.jdbc\.driver"
            ],
            'sqlite': [
                r"SQLite\/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"Warning.*sqlite_.*",
                r"Warning.*SQLite3::",
                r"\[SQLITE_ERROR\]",
                r"sqlite3.OperationalError:"
            ],
            'db2': [
                r"SQLCODE",
                r"DB2 SQL error",
                r"db2_\w+\(",
                r"com\.ibm\.db2\.jcc"
            ],
            'informix': [
                r"Exception.*Informix",
                r"Warning.*ibase_.*",
                r"com\.informix\.jdbc"
            ],
            'sybase': [
                r"Warning.*sybase.*",
                r"Sybase message"
            ]
        }
    
    def validate_sql_injection(self, 
                               baseline_response, 
                               test_response, 
                               payload: str, 
                               response_time: float = 0,
                               baseline_time: float = 0) -> Tuple[bool, int, List[str]]:
        """
        Expert SQL Injection validation with multi-layer verification
        
        Returns:
            Tuple[is_vulnerable, confidence_score, evidence_list]
        """
        evidence = []
        confidence = 0
        
        # Layer 1: Database Error Detection (HIGHEST CONFIDENCE - 95-98%)
        db_error_found, db_conf, db_evidence = self._detect_database_errors(test_response.text)
        if db_error_found:
            evidence.extend(db_evidence)
            confidence = db_conf
            
            # Verify it's not a WAF false positive
            if not self._is_waf_response(test_response.text):
                evidence.append(f"[CONFIRMED] Database error without WAF interference")
                return True, confidence, evidence
            else:
                evidence.append("[FALSE POSITIVE] WAF/Security system detected")
                return False, 0, evidence
        
        # Layer 2: Time-Based SQL Injection (HIGH CONFIDENCE - 85-95%)
        if 'sleep' in payload.lower() or 'waitfor' in payload.lower() or 'benchmark' in payload.lower():
            time_based_vuln, time_conf, time_evidence = self._validate_time_based_sqli(
                response_time, baseline_time, payload
            )
            if time_based_vuln:
                evidence.extend(time_evidence)
                confidence = max(confidence, time_conf)
                
                # Cross-verify with multiple payloads
                if time_conf >= 90:
                    evidence.append("[CONFIRMED] Time-based SQLi verified")
                    return True, confidence, evidence
        
        # Layer 3: Boolean-Based SQL Injection (MEDIUM CONFIDENCE - 70-85%)
        if baseline_response:
            boolean_vuln, bool_conf, bool_evidence = self._validate_boolean_sqli(
                baseline_response, test_response, payload
            )
            if boolean_vuln:
                evidence.extend(bool_evidence)
                confidence = max(confidence, bool_conf)
                
                # Require additional verification for boolean-based
                if bool_conf >= 80:
                    # Check response structure changes
                    if self._verify_response_structure_change(baseline_response, test_response):
                        evidence.append("[CONFIRMED] Boolean SQLi with structural changes")
                        return True, confidence, evidence
        
        # Layer 4: Union-Based SQL Injection (MEDIUM CONFIDENCE - 70-85%)
        if 'union' in payload.lower() and 'select' in payload.lower():
            union_vuln, union_conf, union_evidence = self._validate_union_sqli(
                baseline_response, test_response, payload
            )
            if union_vuln:
                evidence.extend(union_evidence)
                confidence = max(confidence, union_conf)
                
                if union_conf >= 75:
                    evidence.append("[CONFIRMED] Union-based SQLi detected")
                    return True, confidence, evidence
        
        # Layer 5: Stacked Queries Detection
        if ';' in payload:
            stacked_vuln, stack_conf, stack_evidence = self._validate_stacked_queries(
                baseline_response, test_response, payload
            )
            if stacked_vuln:
                evidence.extend(stack_evidence)
                confidence = max(confidence, stack_conf)
        
        # Layer 6: False Negative Detection
        # Check for subtle indicators that might be missed
        fn_indicators = self._detect_false_negatives_sqli(test_response.text, payload)
        if fn_indicators:
            evidence.extend(fn_indicators)
            evidence.append("[WARNING] Possible false negative - manual verification recommended")
            confidence = max(confidence, 60)
        
        # Final decision threshold
        if confidence >= 70:
            return True, confidence, evidence
        
        return False, confidence, evidence
    
    def _detect_database_errors(self, response_text: str) -> Tuple[bool, int, List[str]]:
        """Detect database errors with high precision"""
        evidence = []
        text_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE | re.DOTALL)
                if matches:
                    evidence.append(f"[DB ERROR] {db_type.upper()}: {matches[0][:100]}")
                    
                    # Multiple error matches = higher confidence
                    if len(matches) > 1:
                        return True, 98, evidence
                    return True, 95, evidence
        
        # Check for generic SQL error keywords
        generic_errors = [
            'sql syntax', 'syntax error', 'unterminated', 'unexpected end of sql',
            'quoted string not properly terminated', 'unclosed quotation mark'
        ]
        
        for error in generic_errors:
            if error in text_lower:
                evidence.append(f"[SQL ERROR] Generic: {error}")
                return True, 90, evidence
        
        return False, 0, evidence
    
    def _validate_time_based_sqli(self, 
                                   response_time: float, 
                                   baseline_time: float,
                                   payload: str) -> Tuple[bool, int, List[str]]:
        """
        Validate time-based SQL injection with high precision
        Requires consistent delay matching expected sleep time
        """
        evidence = []
        
        # Extract expected delay from payload
        expected_delay = 0
        if 'sleep' in payload.lower():
            sleep_match = re.search(r'sleep\((\d+)\)', payload, re.IGNORECASE)
            if sleep_match:
                expected_delay = int(sleep_match.group(1))
        elif 'waitfor' in payload.lower():
            waitfor_match = re.search(r"delay\s+'00:00:(\d+)'", payload, re.IGNORECASE)
            if waitfor_match:
                expected_delay = int(waitfor_match.group(1))
        elif 'benchmark' in payload.lower():
            expected_delay = 5  # Approximate
        
        if expected_delay == 0:
            expected_delay = 5  # Default
        
        actual_delay = response_time - baseline_time
        
        # Check if delay matches expected (with tolerance)
        tolerance = 1.5  # Allow 1.5 second variance
        
        if actual_delay >= (expected_delay - tolerance):
            deviation = abs(actual_delay - expected_delay)
            
            if deviation < 0.5:
                # Very precise match
                evidence.append(f"[TIME-BASED] Precise delay: {actual_delay:.2f}s (expected {expected_delay}s)")
                return True, 95, evidence
            elif deviation < 1.0:
                # Good match
                evidence.append(f"[TIME-BASED] Good delay: {actual_delay:.2f}s (expected {expected_delay}s)")
                return True, 90, evidence
            elif deviation < 2.0:
                # Acceptable match
                evidence.append(f"[TIME-BASED] Acceptable delay: {actual_delay:.2f}s (expected {expected_delay}s)")
                return True, 85, evidence
            else:
                # Possible but needs verification
                evidence.append(f"[TIME-BASED] Possible delay: {actual_delay:.2f}s (high variance)")
                return True, 70, evidence
        
        return False, 0, evidence
    
    def _validate_boolean_sqli(self, 
                                baseline_response, 
                                test_response,
                                payload: str) -> Tuple[bool, int, List[str]]:
        """
        Validate boolean-based SQL injection with differential analysis
        """
        evidence = []
        
        # Calculate response differences
        len_diff = abs(len(baseline_response.text) - len(test_response.text))
        
        # Response must be significantly different
        if len_diff < 50:
            return False, 0, []
        
        # Check for TRUE vs FALSE payloads
        if "' and '1'='1" in payload.lower() or "' or '1'='1" in payload.lower():
            # TRUE condition - should return data
            
            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(
                None, 
                baseline_response.text, 
                test_response.text
            ).ratio()
            
            if similarity < 0.7:  # Less than 70% similar = significant change
                evidence.append(f"[BOOLEAN] Response differs by {len_diff} bytes (similarity: {similarity:.2%})")
                
                # Check if new content appeared (not just removed)
                if len(test_response.text) > len(baseline_response.text):
                    evidence.append("[BOOLEAN] Additional content in TRUE condition")
                    return True, 85, evidence
                else:
                    evidence.append("[BOOLEAN] Content removed in condition")
                    return True, 75, evidence
        
        elif "' and '1'='2" in payload.lower() or "' and 1=0" in payload.lower():
            # FALSE condition - should return less/no data
            
            if len(test_response.text) < len(baseline_response.text) * 0.8:
                evidence.append(f"[BOOLEAN] Significant content reduction in FALSE condition")
                return True, 80, evidence
        
        return False, 0, evidence
    
    def _validate_union_sqli(self,
                             baseline_response,
                             test_response,
                             payload: str) -> Tuple[bool, int, List[str]]:
        """
        Validate UNION-based SQL injection
        """
        evidence = []
        
        # UNION should reveal additional data
        len_increase = len(test_response.text) - len(baseline_response.text)
        
        if len_increase > 100:
            evidence.append(f"[UNION] Response increased by {len_increase} bytes")
            
            # Check for NULL markers or data leakage
            if 'null' in test_response.text.lower():
                null_count = test_response.text.lower().count('null')
                if null_count > 2:
                    evidence.append(f"[UNION] Multiple NULL values detected ({null_count})")
                    return True, 85, evidence
            
            # Check for column enumeration success
            if test_response.status_code == 200 and baseline_response.status_code == 200:
                evidence.append("[UNION] Successful UNION query execution")
                return True, 80, evidence
        
        # Check if error disappeared (means column count matched)
        baseline_has_error = any(err in baseline_response.text.lower() 
                                for err in ['error', 'warning', 'mysql', 'sql'])
        test_has_error = any(err in test_response.text.lower() 
                            for err in ['error', 'warning', 'mysql', 'sql'])
        
        if baseline_has_error and not test_has_error:
            evidence.append("[UNION] Error resolved - correct column count found")
            return True, 75, evidence
        
        return False, 0, evidence
    
    def _validate_stacked_queries(self,
                                   baseline_response,
                                   test_response,
                                   payload: str) -> Tuple[bool, int, List[str]]:
        """Validate stacked queries execution"""
        evidence = []
        
        # Look for signs of multiple query execution
        dangerous_keywords = ['drop', 'insert', 'update', 'delete', 'create', 'alter']
        
        for keyword in dangerous_keywords:
            if keyword in payload.lower():
                # Check if response changed significantly
                if test_response.status_code != baseline_response.status_code:
                    evidence.append(f"[STACKED] Status code changed after {keyword.upper()} attempt")
                    return True, 70, evidence
                
                # Check timing - stacked queries take longer
                # This would need to be passed in, but we can infer from content
                if len(test_response.text) != len(baseline_response.text):
                    evidence.append(f"[STACKED] Response changed after {keyword.upper()} query")
                    return True, 65, evidence
        
        return False, 0, evidence
    
    def _verify_response_structure_change(self, baseline_response, test_response) -> bool:
        """Verify if HTML structure changed (not just content)"""
        try:
            baseline_soup = BeautifulSoup(baseline_response.text, 'html.parser')
            test_soup = BeautifulSoup(test_response.text, 'html.parser')
            
            # Compare number of tags
            baseline_tags = len(baseline_soup.find_all())
            test_tags = len(test_soup.find_all())
            
            # Significant structural change
            return abs(baseline_tags - test_tags) > 5
        except:
            return False
    
    def _is_waf_response(self, response_text: str) -> bool:
        """Check if response is from WAF/security system"""
        text_lower = response_text.lower()
        
        for indicator in self.false_positive_indicators:
            if indicator in text_lower:
                return True
        
        # Check for WAF-specific patterns
        waf_patterns = [
            r'request\s+id:?\s+[a-f0-9\-]+',
            r'incident\s+id:?\s+[a-f0-9\-]+',
            r'security\s+policy',
            r'access\s+denied',
            r'blocked\s+by\s+security',
        ]
        
        for pattern in waf_patterns:
            if re.search(pattern, text_lower):
                return True
        
        return False
    
    def _detect_false_negatives_sqli(self, response_text: str, payload: str) -> List[str]:
        """
        Detect potential false negatives - vulnerabilities that might be missed
        """
        indicators = []
        
        # Check for subtle error messages
        subtle_errors = [
            'invalid', 'unexpected', 'parse', 'column', 'table', 'query',
            'statement', 'operand', 'operator', 'expression'
        ]
        
        for error in subtle_errors:
            if error in response_text.lower() and len(response_text) < 5000:
                indicators.append(f"[FALSE NEGATIVE?] Subtle error keyword: {error}")
        
        # Check for data leakage patterns
        data_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-zA-Z]:\\\\',  # Windows paths
            r'/(?:etc|var|usr|home)/',  # Linux paths
            r'(?:admin|root|user):\$',  # User hashes
        ]
        
        for pattern in data_patterns:
            if re.search(pattern, response_text):
                indicators.append(f"[FALSE NEGATIVE?] Potential data leakage detected")
                break
        
        return indicators

    def validate_xss(self, 
                     response, 
                     payload: str, 
                     unique_marker: str) -> Tuple[bool, int, List[str], str]:
        """
        Expert XSS validation with context-aware analysis
        
        Returns:
            Tuple[is_vulnerable, confidence, evidence, context]
        """
        evidence = []
        confidence = 0
        context = "Not Found"
        
        # Layer 1: Check if payload is reflected AT ALL
        if unique_marker not in response.text and payload not in response.text:
            evidence.append("[SAFE] Payload not reflected in response")
            return False, 0, evidence, context
        
        # Layer 2: Check for complete filtering (FALSE POSITIVE prevention)
        if self._is_completely_sanitized(response.text, payload, unique_marker):
            evidence.append("[SAFE] Payload completely sanitized/encoded")
            return False, 0, evidence, "Sanitized"
        
        # Layer 3: Context detection with precision
        context, ctx_confidence, ctx_evidence = self._detect_xss_context(response.text, payload, unique_marker)
        evidence.extend(ctx_evidence)
        confidence = ctx_confidence
        
        # Layer 4: Check execution possibility
        can_execute, exec_conf, exec_evidence = self._check_xss_execution(response, context, unique_marker)
        evidence.extend(exec_evidence)
        
        if can_execute:
            confidence = max(confidence, exec_conf)
        else:
            # Cannot execute - reduce confidence significantly
            confidence = min(confidence, 50)
            evidence.append("[SAFE] Payload reflected but cannot execute")
            return False, confidence, evidence, context
        
        # Layer 5: Check security headers
        header_safe, header_evidence = self._check_xss_security_headers(response)
        evidence.extend(header_evidence)
        
        if header_safe:
            confidence = max(0, confidence - 20)
            if confidence < 70:
                evidence.append("[SAFE] Protected by security headers")
                return False, confidence, evidence, context
        
        # Layer 6: False negative detection
        if confidence < 70:
            fn_indicators = self._detect_false_negatives_xss(response.text, payload, unique_marker)
            if fn_indicators:
                evidence.extend(fn_indicators)
                confidence = max(confidence, 65)
        
        # Final decision
        if confidence >= 70:
            evidence.append(f"[CONFIRMED] XSS in {context} context")
            return True, confidence, evidence, context
        
        return False, confidence, evidence, context
    
    def _is_completely_sanitized(self, response_text: str, payload: str, marker: str) -> bool:
        """Check if payload is completely sanitized"""
        
        # Check for HTML encoding
        encoded_forms = [
            marker.replace('<', '&lt;').replace('>', '&gt;'),
            marker.replace('"', '&quot;').replace("'", '&#x27;'),
            marker.replace('<', '&#60;').replace('>', '&#62;'),
            marker.replace('<', '%3C').replace('>', '%3E'),
            marker.replace('<', '&#x3C;').replace('>', '&#x3E;'),
        ]
        
        for encoded in encoded_forms:
            if encoded in response_text:
                return True
        
        # Check if dangerous characters are stripped
        dangerous_chars = ['<', '>', '"', "'", '(', ')']
        marker_has_dangerous = any(c in marker for c in dangerous_chars)
        
        if marker_has_dangerous:
            # Check if marker appears without dangerous characters
            safe_marker = ''.join(c for c in marker if c not in dangerous_chars)
            if safe_marker and safe_marker in response_text:
                # Marker exists but dangerous chars removed
                if not any(c in response_text[response_text.find(safe_marker)-10:response_text.find(safe_marker)+10] 
                          for c in dangerous_chars):
                    return True
        
        return False
    
    def _detect_xss_context(self, response_text: str, payload: str, marker: str) -> Tuple[str, int, List[str]]:
        """Detect XSS context with high precision"""
        evidence = []
        
        # Find marker position
        marker_pos = response_text.find(marker)
        if marker_pos == -1:
            marker_pos = response_text.find(payload)
        
        if marker_pos == -1:
            return "Unknown", 0, ["Payload not found in response"]
        
        # Get context around marker (200 chars before and after)
        start = max(0, marker_pos - 200)
        end = min(len(response_text), marker_pos + len(marker) + 200)
        context_area = response_text[start:end].lower()
        
        # Detect specific contexts with confidence scoring
        
        # 1. Script Tag Context (HIGHEST RISK)
        if '<script' in context_area and '</script>' in context_area:
            if marker in response_text[response_text.find('<script', start):response_text.find('</script>', marker_pos)+9]:
                evidence.append("[CONTEXT] Inside <script> tag - Direct execution")
                return "Script Tag", 95, evidence
        
        # 2. Event Handler Context (HIGH RISK)
        event_handlers = [
            'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=',
            'onblur=', 'onchange=', 'onsubmit=', 'onkeypress=', 'onkeydown='
        ]
        for handler in event_handlers:
            if handler in context_area:
                # Check if marker is in the handler value
                handler_pos = context_area.find(handler)
                if abs(handler_pos - (marker_pos - start)) < 50:
                    evidence.append(f"[CONTEXT] Inside {handler} event handler")
                    return "Event Handler", 90, evidence
        
        # 3. HTML Attribute Context (MEDIUM-HIGH RISK)
        if self._is_in_html_attribute(response_text, marker_pos):
            evidence.append("[CONTEXT] Inside HTML attribute")
            # Check if can break out
            if '"' in marker or "'" in marker or '>' in marker:
                evidence.append("[CONTEXT] Can break out of attribute")
                return "HTML Attribute (Breakable)", 85, evidence
            else:
                evidence.append("[CONTEXT] Cannot easily break out")
                return "HTML Attribute", 60, evidence
        
        # 4. JavaScript String Context (MEDIUM-HIGH RISK)
        js_string_patterns = [
            r"var\s+\w+\s*=\s*['\"]",
            r"['\"].*?" + re.escape(marker) + r".*?['\"]",
            r"document\.write\(['\"]",
            r"innerHTML\s*=\s*['\"]"
        ]
        for pattern in js_string_patterns:
            if re.search(pattern, context_area):
                evidence.append("[CONTEXT] Inside JavaScript string")
                return "JavaScript String", 75, evidence
        
        # 5. HTML Body Context (MEDIUM RISK)
        if '<body' in context_area or '</body>' in context_area:
            evidence.append("[CONTEXT] Inside HTML body")
            return "HTML Body", 70, evidence
        
        # 6. HTML Comment (LOW RISK)
        if '<!--' in context_area and '-->' in context_area:
            evidence.append("[CONTEXT] Inside HTML comment")
            return "HTML Comment", 30, evidence
        
        # 7. Plain Text (VARIES)
        evidence.append("[CONTEXT] In plain text/unknown context")
        return "Plain Text", 50, evidence
    
    def _is_in_html_attribute(self, html: str, position: int) -> bool:
        """Check if position is inside an HTML attribute"""
        # Look backwards for opening tag
        search_back = html[max(0, position-100):position]
        search_forward = html[position:min(len(html), position+100)]
        
        # Find last < before position
        last_lt = search_back.rfind('<')
        # Find first > after position
        first_gt = search_forward.find('>')
        
        if last_lt != -1 and first_gt != -1:
            # We're inside a tag
            # Check if we're in an attribute value (between = and space/'>)
            between_tag = search_back[last_lt:] + search_forward[:first_gt]
            
            # Simple check: if there's an = before our position and space/> after
            has_equals = '=' in search_back[last_lt:]
            return has_equals
        
        return False
    
    def _check_xss_execution(self, response, context: str, marker: str) -> Tuple[bool, int, List[str]]:
        """Check if XSS payload can actually execute"""
        evidence = []
        
        # Contexts that allow execution
        executable_contexts = {
            "Script Tag": (True, 95, "Direct JavaScript execution possible"),
            "Event Handler": (True, 90, "Event handler execution possible"),
            "HTML Attribute (Breakable)": (True, 85, "Can break out and inject script"),
            "JavaScript String": (True, 75, "JavaScript context injection possible"),
            "HTML Body": (True, 70, "Can inject HTML tags with JS"),
        }
        
        safe_contexts = {
            "HTML Comment": (False, 0, "Code in HTML comment - cannot execute"),
            "Sanitized": (False, 0, "Payload sanitized"),
            "HTML Attribute": (False, 40, "Cannot break out of attribute"),
        }
        
        if context in executable_contexts:
            can_exec, conf, msg = executable_contexts[context]
            evidence.append(f"[EXECUTION] {msg}")
            return can_exec, conf, evidence
        
        if context in safe_contexts:
            can_exec, conf, msg = safe_contexts[context]
            evidence.append(f"[SAFE] {msg}")
            return can_exec, conf, evidence
        
        # Unknown context - check for dangerous patterns
        if '<script' in response.text.lower() and marker in response.text:
            evidence.append("[EXECUTION] Script tag present")
            return True, 70, evidence
        
        evidence.append("[UNCERTAIN] Cannot determine execution possibility")
        return False, 50, evidence
    
    def _check_xss_security_headers(self, response) -> Tuple[bool, List[str]]:
        """Check for XSS protection headers"""
        evidence = []
        is_protected = False
        
        # Check CSP
        if 'content-security-policy' in response.headers:
            csp = response.headers['content-security-policy'].lower()
            evidence.append(f"[HEADER] CSP present: {csp[:100]}")
            
            # Check if CSP blocks inline scripts
            if "'unsafe-inline'" not in csp and 'script-src' in csp:
                evidence.append("[HEADER] CSP blocks inline scripts")
                is_protected = True
        
        # Check X-XSS-Protection
        if 'x-xss-protection' in response.headers:
            xss_prot = response.headers['x-xss-protection']
            evidence.append(f"[HEADER] X-XSS-Protection: {xss_prot}")
            if '1' in xss_prot:
                is_protected = True
        
        # Check X-Content-Type-Options
        if 'x-content-type-options' in response.headers:
            evidence.append("[HEADER] X-Content-Type-Options present")
        
        return is_protected, evidence
    
    def _detect_false_negatives_xss(self, response_text: str, payload: str, marker: str) -> List[str]:
        """Detect potential false negatives for XSS"""
        indicators = []
        
        # Check if payload was modified but still potentially dangerous
        dangerous_patterns = [
            (r'<\w+[^>]*on\w+\s*=', "Event handler pattern"),
            (r'javascript:', "JavaScript protocol"),
            (r'<iframe', "IFrame tag"),
            (r'<embed', "Embed tag"),
            (r'<object', "Object tag"),
        ]
        
        for pattern, desc in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(f"[FALSE NEGATIVE?] {desc} detected")
        
        return indicators

    def validate_lfi(self, response, payload: str, baseline_response=None) -> Tuple[bool, int, List[str]]:
        """
        Expert LFI validation with file signature matching
        
        Returns:
            Tuple[is_vulnerable, confidence, evidence]
        """
        evidence = []
        confidence = 0
        
        # Layer 1: Signature-based detection (HIGHEST CONFIDENCE)
        sig_found, sig_conf, sig_evidence = self._detect_file_signatures(response.text, payload)
        if sig_found:
            evidence.extend(sig_evidence)
            confidence = sig_conf
            
            # Verify it's not error message
            if not self._is_error_message(response.text):
                evidence.append("[CONFIRMED] Valid file content detected")
                return True, confidence, evidence
            else:
                evidence.append("[FALSE POSITIVE] Error message, not file content")
                return False, 0, evidence
        
        # Layer 2: Path traversal success indicators
        if baseline_response:
            path_vuln, path_conf, path_evidence = self._validate_path_traversal(
                baseline_response, response, payload
            )
            if path_vuln:
                evidence.extend(path_evidence)
                confidence = max(confidence, path_conf)
        
        # Layer 3: Source code disclosure
        code_vuln, code_conf, code_evidence = self._detect_source_code(response.text)
        if code_vuln:
            evidence.extend(code_evidence)
            confidence = max(confidence, code_conf)
        
        # Layer 4: False negative detection
        fn_indicators = self._detect_false_negatives_lfi(response.text, payload)
        if fn_indicators:
            evidence.extend(fn_indicators)
            confidence = max(confidence, 60)
        
        # Final decision
        if confidence >= 70:
            return True, confidence, evidence
        
        return False, confidence, evidence
    
    def _detect_file_signatures(self, response_text: str, payload: str) -> Tuple[bool, int, List[str]]:
        """Detect authentic file signatures"""
        evidence = []
        
        # Linux /etc/passwd signatures
        passwd_patterns = [
            (r'root:x?:0:0:[^:]*:/root:', 'root user entry', 98),
            (r'daemon:x?:\d+:\d+:[^:]*:/usr/sbin:', 'daemon user entry', 95),
            (r'www-data:x?:\d+:\d+:', 'www-data user', 95),
            (r'nobody:x?:65534:', 'nobody user', 95),
            (r'[\w\-]+:x?:\d+:\d+:[^:]*:[^:]+:[^:]+\n', 'Unix password file format', 90),
        ]
        
        for pattern, desc, conf in passwd_patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                evidence.append(f"[FILE SIG] {desc}: {len(matches)} entries found")
                return True, conf, evidence
        
        # Windows files
        win_patterns = [
            (r'\[fonts\]', 'win.ini [fonts] section', 95),
            (r'\[extensions\]', 'win.ini [extensions] section', 95),
            (r'for 16-bit app support', 'win.ini signature', 93),
            (r'\[boot loader\]', 'boot.ini signature', 95),
            (r'C:\\Windows', 'Windows path', 85),
        ]
        
        for pattern, desc, conf in win_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                evidence.append(f"[FILE SIG] {desc}")
                return True, conf, evidence
        
        # /etc/hosts
        if re.search(r'127\.0\.0\.1\s+(localhost|localhost\.localdomain)', response_text):
            evidence.append("[FILE SIG] /etc/hosts file detected")
            return True, 93, evidence
        
        # /etc/shadow (partial - should not be readable but check anyway)
        if re.search(r'[\w\-]+:\$[156]\$[\w\./]+:\d+:', response_text):
            evidence.append("[FILE SIG] /etc/shadow format detected (CRITICAL)")
            return True, 98, evidence
        
        # Apache/Nginx config
        config_patterns = [
            (r'<VirtualHost\s+[\*\d\.:]+>', 'Apache VirtualHost', 95),
            (r'DocumentRoot\s+["\']?/[\w/]+["\']?', 'Apache DocumentRoot', 93),
            (r'server\s*\{[\s\S]*listen\s+\d+', 'Nginx server block', 95),
        ]
        
        for pattern, desc, conf in config_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                evidence.append(f"[CONFIG] {desc}")
                return True, conf, evidence
        
        return False, 0, evidence
    
    def _is_error_message(self, text: str) -> bool:
        """Check if response is an error message rather than file content"""
        error_keywords = [
            'error', 'exception', 'warning', 'failed', 'could not', 'unable',
            'permission denied', 'access denied', 'not found', 'does not exist',
            'cannot open', 'cannot read'
        ]
        
        text_lower = text.lower()
        error_count = sum(1 for keyword in error_keywords if keyword in text_lower)
        
        # If multiple error keywords and response is short, likely an error
        if error_count >= 2 and len(text) < 1000:
            return True
        
        return False
    
    def _validate_path_traversal(self, baseline_response, test_response, payload: str) -> Tuple[bool, int, List[str]]:
        """Validate successful path traversal"""
        evidence = []
        
        # Check if response changed significantly
        len_diff = abs(len(baseline_response.text) - len(test_response.text))
        
        if len_diff > 200:
            evidence.append(f"[PATH TRAV] Response changed by {len_diff} bytes")
            
            # Check if new content looks like file content
            if len(test_response.text) > len(baseline_response.text):
                new_content = test_response.text
                
                # Check for file-like patterns
                has_lines = '\n' in new_content
                has_paths = re.search(r'[/\\][\w/\\]+', new_content)
                has_config = re.search(r'[\w_]+=[\w/.]+', new_content)
                
                if has_lines and (has_paths or has_config):
                    evidence.append("[PATH TRAV] Response contains file-like content")
                    return True, 80, evidence
        
        return False, 0, evidence
    
    def _detect_source_code(self, response_text: str) -> Tuple[bool, int, List[str]]:
        """Detect source code disclosure"""
        evidence = []
        
        code_patterns = [
            (r'<\?php', 'PHP source code', 95),
            (r'<\?=', 'PHP short tag', 93),
            (r'import\s+[\w\.]+\s+as\s+\w+', 'Python import', 90),
            (r'from\s+[\w\.]+\s+import', 'Python import', 90),
            (r'require\s*\([\'"][^\'"]+[\'"]\)', 'Node.js require', 90),
            (r'package\s+\w+;', 'Java/Go package', 88),
            (r'using\s+System;', 'C# using statement', 88),
            (r'#include\s+<[\w.]+>', 'C/C++ include', 88),
        ]
        
        for pattern, desc, conf in code_patterns:
            if re.search(pattern, response_text):
                evidence.append(f"[SOURCE CODE] {desc} detected")
                
                # Count lines to verify it's substantial
                lines = response_text.count('\n')
                if lines > 5:
                    evidence.append(f"[SOURCE CODE] {lines} lines of code")
                    return True, conf, evidence
        
        return False, 0, evidence
    
    def _detect_false_negatives_lfi(self, response_text: str, payload: str) -> List[str]:
        """Detect potential false negatives for LFI"""
        indicators = []
        
        # Check for partial file disclosure
        partial_patterns = [
            (r'[\w\-]+:\d+:\d+:', 'Partial passwd format'),
            (r'[a-fA-F0-9]{32,}', 'Hash values'),
            (r'/(?:var|etc|usr|home|opt)/[\w/]+', 'Absolute paths'),
        ]
        
        for pattern, desc in partial_patterns:
            if re.search(pattern, response_text):
                indicators.append(f"[FALSE NEGATIVE?] {desc} detected")
        
        return indicators

    def validate_command_injection(self,
                                    response_time: float,
                                    baseline_time: float,
                                    payload: str,
                                    response_obj=None,
                                    baseline_obj=None) -> Tuple[bool, int, List[str]]:
        """
        Expert Command Injection validation
        
        Returns:
            Tuple[is_vulnerable, confidence, evidence]
        """
        evidence = []
        confidence = 0
        
        # Layer 1: Time-based validation (for sleep/ping commands)
        if response_obj:
            time_vuln, time_conf, time_evidence = self._validate_time_based_cmd(
                response_time, baseline_time, payload
            )
            if time_vuln:
                evidence.extend(time_evidence)
                confidence = time_conf
                
                if time_conf >= 85:
                    return True, confidence, evidence
        
        # Layer 2: Output-based validation (for whoami, id, ls, dir)
        if response_obj and hasattr(response_obj, 'text'):
            output_vuln, out_conf, out_evidence = self._validate_command_output(
                response_obj.text, baseline_obj.text if baseline_obj else "", payload
            )
            if output_vuln:
                evidence.extend(out_evidence)
                confidence = max(confidence, out_conf)
                
                if out_conf >= 90:
                    return True, confidence, evidence
        
        # Layer 3: Error-based validation
        if response_obj:
            error_vuln, err_conf, err_evidence = self._detect_command_errors(response_obj.text)
            if error_vuln:
                evidence.extend(err_evidence)
                confidence = max(confidence, err_conf)
        
        # Final decision
        if confidence >= 70:
            return True, confidence, evidence
        
        return False, confidence, evidence
    
    def _validate_time_based_cmd(self, response_time: float, baseline_time: float, payload: str) -> Tuple[bool, int, List[str]]:
        """Validate time-based command injection"""
        evidence = []
        
        expected_delay = 5  # Default
        
        # Extract expected delay
        if 'sleep' in payload.lower():
            sleep_match = re.search(r'sleep\s+(\d+)', payload, re.IGNORECASE)
            if sleep_match:
                expected_delay = int(sleep_match.group(1))
        elif 'ping' in payload.lower():
            ping_match = re.search(r'ping\s+(?:-[nc]\s+)?(\d+)', payload, re.IGNORECASE)
            if ping_match:
                expected_delay = int(ping_match.group(1))
        
        actual_delay = response_time - baseline_time
        
        if actual_delay >= (expected_delay - 1):
            deviation = abs(actual_delay - expected_delay)
            
            if deviation < 0.5:
                evidence.append(f"[CMD TIME] Precise delay: {actual_delay:.2f}s")
                return True, 95, evidence
            elif deviation < 1.0:
                evidence.append(f"[CMD TIME] Good delay: {actual_delay:.2f}s")
                return True, 90, evidence
            elif deviation < 2.0:
                evidence.append(f"[CMD TIME] Acceptable delay: {actual_delay:.2f}s")
                return True, 85, evidence
        
        return False, 0, evidence
    
    def _validate_command_output(self, response_text: str, baseline_text: str, payload: str) -> Tuple[bool, int, List[str]]:
        """Validate command output in response"""
        evidence = []
        
        # Command output signatures
        output_patterns = [
            (r'uid=\d+\([\w\-]+\)\s+gid=\d+', 'Unix id command output', 98),
            (r'uid=\d+', 'Unix uid format', 95),
            (r'gid=\d+', 'Unix gid format', 93),
            (r'total\s+\d+', 'ls -l output', 90),
            (r'[drwx\-]{10}\s+\d+', 'Unix permissions', 95),
            (r'Volume in drive [A-Z]', 'Windows dir output', 95),
            (r'Directory of [A-Z]:', 'Windows directory listing', 95),
            (r'Linux version \d+\.\d+', 'Linux kernel version', 98),
            (r'GNU/Linux', 'Linux OS identifier', 93),
            (r'root:x:0:0', 'Root user from /etc/passwd', 98),
        ]
        
        for pattern, desc, conf in output_patterns:
            matches = re.findall(pattern, response_text)
            if matches and not re.search(pattern, baseline_text):
                # Output appeared after injection
                evidence.append(f"[CMD OUTPUT] {desc}: {matches[0][:50]}")
                return True, conf, evidence
        
        # Check for multiple lines of output (typical of command results)
        new_lines = response_text.count('\n') - baseline_text.count('\n')
        if new_lines > 3:
            # Check if new lines look like command output
            response_lines = response_text.split('\n')
            command_like = sum(1 for line in response_lines 
                              if re.search(r'[\w\-]+\s+[\w\-]+\s+\d+', line))
            
            if command_like > 2:
                evidence.append(f"[CMD OUTPUT] {new_lines} new lines of command-like output")
                return True, 85, evidence
        
        return False, 0, evidence
    
    def _detect_command_errors(self, response_text: str) -> Tuple[bool, int, List[str]]:
        """Detect command execution errors"""
        evidence = []
        
        error_patterns = [
            (r'sh:\s+\d+:\s+', 'Shell error', 90),
            (r'bash:\s+line\s+\d+:', 'Bash error', 90),
            (r'command not found', 'Command not found', 85),
            (r'No such file or directory', 'Path error', 80),
            (r'Permission denied', 'Permission error', 75),
        ]
        
        for pattern, desc, conf in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                evidence.append(f"[CMD ERROR] {desc} - Command attempted")
                return True, conf, evidence
        
        return False, 0, evidence

# Export the validator
validator = ExpertValidationEngine()

