"""Behavioral tests for the bounded SROS2 source-policy adapter."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from coaudit.policy import load_policy


def document(profiles: str, *, enclave: str = "/robot") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<policy version="0.2.0">\n<enclaves>\n'
        f'<enclave path="{enclave}">\n<profiles>\n{profiles}\n'
        '</profiles>\n</enclave>\n</enclaves>\n</policy>'
    )


def profile(rules: str = "", *, ns: str = "/", node: str = "controller") -> str:
    return f'<profile ns="{ns}" node="{node}">\n{rules}\n</profile>'


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "policy.xml"

    def load(self, xml: str | bytes):
        data = xml.encode("utf-8") if isinstance(xml, str) else xml
        self.path.write_bytes(data)
        return load_policy(self.path)

    def assert_value(self, policy, name, op, expected, enclave="/robot"):
        result = policy.check(enclave, name, op)
        self.assertIs(result["value"], expected, result)
        self.assertTrue(result["reasons"])
        self.assertIsInstance(result["sources"], list)
        return result

    def test_exact_topics_roles_default_deny_and_hash(self):
        xml = document(profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>'))
        policy = self.load(xml)
        self.assertEqual(policy.issues, [])
        self.assertEqual(policy.sha256, hashlib.sha256(xml.encode()).hexdigest())
        self.assertEqual(policy.enclaves, ("/robot",))
        allowed = self.assert_value(policy, "/cmd", "publish", True)
        self.assertTrue(any("#L" in source for source in allowed["sources"]))
        self.assert_value(policy, "/cmd", "subscribe", False)
        self.assert_value(policy, "/cmd_extra", "publish", False)
        self.assert_value(policy, "/cmd", "request", False)

    def test_relative_absolute_and_private_names_match_reference_expansion(self):
        policy = self.load(document(profile(
            '<topics publish="ALLOW"><topic>scan</topic><topic>/clock</topic>'
            '<topic>~/state</topic></topics>', ns="/fleet/robot/", node="nav")))
        for name in ("/fleet/robot/scan", "/clock", "/fleet/robot/nav/state"):
            with self.subTest(name=name):
                self.assert_value(policy, name, "publish", True)
        self.assert_value(policy, "/scan", "publish", False)

    def test_service_client_and_server_roles_are_not_topic_directions(self):
        policy = self.load(document(profile(
            '<services request="ALLOW"><service>stop</service></services>'
            '<services reply="ALLOW"><service>/health</service></services>')))
        self.assert_value(policy, "/stop", "request", True)
        self.assert_value(policy, "/stop", "reply", False)
        self.assert_value(policy, "/health", "reply", True)
        self.assert_value(policy, "/health", "request", False)
        self.assert_value(policy, "/stop", "publish", False)

    def test_action_call_grants_three_client_roles_and_two_subscriptions(self):
        policy = self.load(document(profile('<actions call="ALLOW"><action>navigate</action></actions>')))
        for suffix in ("send_goal", "cancel_goal", "get_result"):
            with self.subTest(suffix=suffix):
                self.assert_value(policy, "/navigate/_action/" + suffix, "request", True)
                self.assert_value(policy, "/navigate/_action/" + suffix, "reply", False)
        for suffix in ("feedback", "status"):
            self.assert_value(policy, "/navigate/_action/" + suffix, "subscribe", True)
            self.assert_value(policy, "/navigate/_action/" + suffix, "publish", False)
        self.assert_value(policy, "/navigate", "request", False)

    def test_action_execute_grants_server_roles_and_publications(self):
        policy = self.load(document(profile(
            '<actions execute="ALLOW"><action>~/navigate</action></actions>', ns="/robot", node="nav")))
        for suffix in ("send_goal", "cancel_goal", "get_result"):
            self.assert_value(policy, "/robot/nav/navigate/_action/" + suffix, "reply", True)
            self.assert_value(policy, "/robot/nav/navigate/_action/" + suffix, "request", False)
        for suffix in ("feedback", "status"):
            self.assert_value(policy, "/robot/nav/navigate/_action/" + suffix, "publish", True)
            self.assert_value(policy, "/robot/nav/navigate/_action/" + suffix, "subscribe", False)

    def test_action_deny_and_explicit_protocol_denies_override_allows(self):
        policy = self.load(document(profile(
            '<actions call="ALLOW"><action>/navigate</action></actions>'
            '<services request="DENY"><service>/navigate/_action/cancel_goal</service></services>'
            '<topics subscribe="DENY"><topic>/navigate/_action/feedback</topic></topics>')))
        self.assertEqual(policy.issues, [])
        self.assert_value(policy, "/navigate/_action/cancel_goal", "request", False)
        self.assert_value(policy, "/navigate/_action/get_result", "request", True)
        self.assert_value(policy, "/navigate/_action/feedback", "subscribe", False)
        denied_action = self.load(document(profile(
            '<services request="ALLOW"><service>/navigate/_action/send_goal</service></services>'
            '<actions call="DENY"><action>/navigate</action></actions>')))
        self.assert_value(denied_action, "/navigate/_action/send_goal", "request", False)

    def test_enclave_union_and_deny_precedence_are_order_independent(self):
        a = profile('<topics publish="ALLOW"><topic>/cmd</topic><topic>/scan</topic></topics>', node="a")
        b = profile('<topics publish="DENY"><topic>/cmd</topic></topics>', node="b")
        for body in (a + b, b + a):
            with self.subTest(order=body[:50]):
                policy = self.load(document(body))
                self.assertEqual(policy.issues, [])
                denied = self.assert_value(policy, "/cmd", "publish", False)
                self.assertEqual(len(denied["sources"]), 2)
                self.assert_value(policy, "/scan", "publish", True)

    def test_duplicate_rules_are_idempotent_but_duplicate_profile_is_unknown(self):
        rule = '<topics publish="ALLOW"><topic>/cmd</topic><topic>/cmd</topic></topics>'
        policy = self.load(document(profile(rule + rule)))
        self.assertEqual(policy.issues, [])
        self.assert_value(policy, "/cmd", "publish", True)
        duplicate = self.load(document(profile(rule) + profile('')))
        self.assert_value(duplicate, "/cmd", "publish", None)
        self.assertTrue(any("DUPLICATE_PROFILE" in issue for issue in duplicate.issues))

    def test_empty_profile_is_valid_default_deny_missing_enclave_is_unknown(self):
        policy = self.load(document(profile()))
        self.assertEqual(policy.issues, [])
        self.assert_value(policy, "/cmd", "publish", False)
        self.assert_value(policy, "/cmd", "publish", None, enclave="/missing")

    def test_missing_operation_attribute_does_not_grant_permission(self):
        policy = self.load(document(profile('<topics><topic>/cmd</topic></topics>')))
        self.assertEqual(policy.issues, [])
        self.assert_value(policy, "/cmd", "publish", False)

    def test_unsupported_patterns_taint_enclave_even_beside_exact_allow(self):
        for expression in ("*", "/robot/*", "/x?", "/[ab]", "/{name}/cmd"):
            with self.subTest(expression=expression):
                policy = self.load(document(profile(
                    '<topics publish="ALLOW"><topic>/cmd</topic></topics>'
                    f'<topics publish="DENY"><topic>{expression}</topic></topics>')))
                self.assert_value(policy, "/cmd", "publish", None)
                self.assert_value(policy, "/anything", "subscribe", None)
                self.assertTrue(any("UNSUPPORTED_NAME_PATTERN" in issue for issue in policy.issues))

    def test_unsupported_enclave_does_not_poison_independent_complete_enclave(self):
        bad = '<enclave path="/bad"><profiles>' + profile('<topics publish="DENY"><topic>*</topic></topics>') + '</profiles></enclave>'
        good = '<enclave path="/good"><profiles>' + profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>') + '</profiles></enclave>'
        policy = self.load('<policy version="0.2.0"><enclaves>' + bad + good + '</enclaves></policy>')
        self.assertTrue(policy.issues)
        self.assert_value(policy, "/cmd", "publish", None, enclave="/bad")
        self.assert_value(policy, "/cmd", "publish", True, enclave="/good")

    def test_xinclude_xml_base_metadata_and_transport_layout_are_unknown(self):
        normal = document(profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>'))
        variants = (
            normal.replace('</profile>', '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="absent.xml"/></profile>'),
            normal.replace('<profile ', '<profile xml:base="other/" '),
            normal.replace('</profiles>', '<metadata/></profiles>'),
            normal.replace('<profiles>', '<profiles type="dds">'),
            normal.replace('</profiles>', '</profiles><profiles>' + profile(node="other") + '</profiles>'),
        )
        for xml in variants:
            with self.subTest(xml=xml):
                policy = self.load(xml)
                self.assert_value(policy, "/cmd", "publish", None)
                self.assertTrue(policy.issues)

    def test_remap_unknown_attributes_and_wrong_qualifiers_are_never_ignored(self):
        for rules in (
            '<topics publish="allow"><topic>/cmd</topic></topics>',
            '<topics publish="ALLOW" remap="/else"><topic>/cmd</topic></topics>',
            '<remap from="/old" to="/cmd"/><topics publish="ALLOW"><topic>/cmd</topic></topics>',
            '<topics publish="ALLOW"><topic strange="yes">/cmd</topic></topics>',
        ):
            with self.subTest(rules=rules):
                policy = self.load(document(profile(rules)))
                self.assert_value(policy, "/cmd", "publish", None)

    def test_invalid_resource_syntax_is_not_normalized_into_grants(self):
        for expression in ("", " /cmd", "/cmd ", "/a//b", "/a/../b", "/", "~", "~private", "/9name", "/non-ascii-名", "/" + "a" * 255):
            with self.subTest(expression=expression):
                policy = self.load(document(profile(f'<topics publish="ALLOW"><topic>{expression}</topic></topics>')))
                self.assertTrue(policy.issues)
                self.assert_value(policy, "/cmd", "publish", None)

    def test_invalid_profile_names_and_non_absolute_namespaces_are_unknown(self):
        for ns, node in (("relative", "node"), ("/x//", "node"), ("", "node"), ("/", "x/y"), ("/", "9node")):
            with self.subTest(ns=ns, node=node):
                policy = self.load(document(profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>', ns=ns, node=node)))
                self.assert_value(policy, "/cmd", "publish", None)

    def test_structural_errors_and_namespaced_roots_never_yield_default_deny(self):
        for xml in (
            '<policy version="0.2.0"><enclaves/></policy>',
            '<policy version="0.2.0"><enclaves><enclave path="/robot"><profiles/></enclave></enclaves></policy>',
            document(profile('<topics publish="ALLOW"/>')),
            document(profile('<topics publish="ALLOW"><service>/cmd</service></topics>')),
            document(profile('<topics publish="ALLOW"><topic><nested>/cmd</nested></topic></topics>')),
            document(profile()).replace('<policy ', '<policy xmlns="urn:unsupported" '),
            document(profile()).replace('version="0.2.0"', 'version="1.0"'),
            document(profile()).replace('<enclaves>', '<enclaves>unexpected'),
            document(profile()).replace('</policy>', '<unknown/></policy>'),
            '<policy version="0.2.0"><enclaves><enclave path="relative"/></enclaves></policy>',
        ):
            with self.subTest(xml=xml):
                policy = self.load(xml)
                self.assertTrue(policy.issues)
                self.assert_value(policy, "/cmd", "publish", None)

    def test_duplicate_enclave_is_not_merged_silently(self):
        e = '<enclave path="/robot"><profiles>' + profile() + '</profiles></enclave>'
        policy = self.load('<policy version="0.2.0"><enclaves>' + e + e + '</enclaves></policy>')
        self.assert_value(policy, "/cmd", "publish", None)
        self.assertTrue(any("DUPLICATE_ENCLAVE" in issue for issue in policy.issues))

    def test_bad_queries_return_unknown_without_mutating_policy(self):
        policy = self.load(document(profile()))
        for enclave, resource, operation in (
            ("robot", "/cmd", "publish"), ("/robot/../other", "/cmd", "publish"),
            ("/robot", "cmd", "publish"), ("/robot", "/cmd/", "publish"),
            ("/robot", "/cmd", "call"), ("/robot", "/cmd", []),
            (None, "/cmd", "publish"), ("/robot", None, "publish"),
        ):
            with self.subTest(query=(enclave, resource, operation)):
                result = policy.check(enclave, resource, operation)
                self.assertIsNone(result["value"])
        self.assertEqual(policy.issues, [])
        self.assert_value(policy, "/cmd", "publish", False)

    def test_dtd_and_entities_are_rejected_without_following_external_sources(self):
        for declaration in (
            '<!DOCTYPE policy>',
            '<!DOCTYPE policy [<!ENTITY name "cmd">]>',
            '<!DOCTYPE policy SYSTEM "file:///never-read-by-this-parser">',
        ):
            with self.subTest(declaration=declaration):
                xml = declaration + document(profile()).split('?>\n', 1)[1]
                policy = self.load(xml)
                self.assert_value(policy, "/cmd", "publish", None)
                self.assertTrue(any("POLICY_XML_ERROR" in issue for issue in policy.issues))

    def test_malformed_xml_duplicate_attributes_and_invalid_encoding_are_unknown(self):
        for xml in (
            b'<policy', b'', b'\xff\xfe',
            document(profile()).replace('<policy version=', '<policy version="0.2.0" version='),
            document(profile()).replace('encoding="UTF-8"', 'encoding="UTF-16"'),
            document(profile()).replace('<policy ', '<?unexpected value?><policy '),
            document(profile()).replace('<profile ', '<profile bad="&undeclared;" '),
        ):
            with self.subTest(xml=xml):
                policy = self.load(xml)
                self.assert_value(policy, "/cmd", "publish", None)

    def test_unused_namespace_comment_and_utf8_bom_are_safe(self):
        xml = document(profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>'))
        xml = xml.replace('<policy ', '<policy xmlns:xi="http://www.w3.org/2001/XInclude" ')
        xml = xml.replace('<enclaves>', '<!-- explanatory comment --><enclaves>')
        policy = self.load(b'\xef\xbb\xbf' + xml.encode())
        self.assertEqual(policy.issues, [])
        self.assert_value(policy, "/cmd", "publish", True)

    def test_input_size_depth_and_element_caps_prevent_partial_success(self):
        xml = document(profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>'))
        with patch('coaudit.policy.MAX_XML_BYTES', 30):
            policy = self.load(xml)
            self.assertIsNone(policy.sha256)
            self.assert_value(policy, "/cmd", "publish", None)
        with patch('coaudit.policy.MAX_XML_DEPTH', 3):
            policy = self.load(xml)
            self.assert_value(policy, "/cmd", "publish", None)
        with patch('coaudit.policy.MAX_XML_ELEMENTS', 3):
            policy = self.load(xml)
            self.assert_value(policy, "/cmd", "publish", None)

    def test_read_error_is_a_reportable_unknown(self):
        policy = load_policy(Path(self.temp.name) / 'missing.xml')
        self.assertIsNone(policy.sha256)
        self.assertTrue(any("POLICY_READ_ERROR" in issue for issue in policy.issues))
        self.assert_value(policy, "/cmd", "publish", None)

    def test_returned_lists_cannot_rewrite_later_audit_results(self):
        policy = self.load(document(profile('<topics publish="ALLOW"><topic>/cmd</topic></topics>')))
        result = policy.check('/robot', '/cmd', 'publish')
        result['sources'].clear()
        result['reasons'].append('changed')
        policy.issues.append('changed')
        self.assertEqual(policy.issues, [])
        again = self.assert_value(policy, '/cmd', 'publish', True)
        self.assertTrue(again['sources'])
        self.assertNotIn('changed', again['reasons'])


if __name__ == "__main__":
    unittest.main()
