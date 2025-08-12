# tests/test_utils.py
import pytest
from api.policy.opa_client import _normalize

# This file is dedicated to testing utility functions across the application.
# We start with the _normalize function from the OPA client.

@pytest.mark.parametrize("input_data, expected_output", [
    # Test case 1: None should result in an empty list.
    (None, []),
    
    # Test case 2: A list of strings should remain unchanged.
    (["reason one", "reason two"], ["reason one", "reason two"]),
    
    # Test case 3: An empty list should remain an empty list.
    ([], []),
    
    # Test case 4: A boolean 'True' should result in a generic deny message.
    (True, ["policy deny"]),
    
    # Test case 5: A boolean 'False' should result in an empty list (allow).
    (False, []),
    
    # Test case 6: A set of strings should be converted to a list of strings.
    ({"set reason 1", "set reason 2"}, ["set reason 1", "set reason 2"]),
    
    # Test case 7: A single string should be wrapped in a list.
    ("a single deny reason", ["a single deny reason"]),
    
    # Test case 8: A dictionary with boolean 'True' values should use the keys as reasons.
    ({"deny_A": True, "deny_B": False, "deny_C": True}, ["deny_A", "deny_C"]),
    
    # Test case 9: A dictionary with a list of strings.
    ({"reasons": ["list reason 1", "list reason 2"]}, ["list reason 1", "list reason 2"]),
    
    # Test case 10: A dictionary with a set of strings.
    ({"reasons": {"set reason A", "set reason B"}}, ["set reason A", "set reason B"]),
    
    # Test case 11: A dictionary with a single string value.
    ({"reason": "string reason"}, ["string reason"]),
    
    # Test case 12: A dictionary with mixed value types.
    (
        {
            "main_deny": True, 
            "other_reasons": ["list reason"], 
            "ignored": False, 
            "more_reasons": {"set reason"}
        }, 
        ["main_deny", "list reason", "set reason"]
    ),
    
    # Test case 13: An integer should be converted to a string and wrapped in a list.
    (12345, ["12345"]),
])
def test_normalize_function(input_data, expected_output):
    """
    Tests the _normalize helper function from the OPA client to ensure it correctly
    handles various OPA response formats and converts them to a consistent list of strings.
    """
    # The output order of sets and dicts is not guaranteed, so we sort both lists
    # to ensure the comparison is consistent and order-independent.
    normalized_result = sorted(_normalize(input_data))
    expected = sorted(expected_output)
    
    assert normalized_result == expected
