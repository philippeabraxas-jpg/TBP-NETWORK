"""Invariants of the two cloud templates of the DEV-TEST site (azure.bicep, aws.cfn.yaml) and of their guides.

These do not replace `az deployment group validate` / `aws cloudformation validate-template` (the guides begin with
them): they pin what must never change silently — what is open, to whom — and that the guides say what the
templates do. Standard library only; run from anywhere:  python3 -m unittest -v test_templates
"""
import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).resolve().parent
MACHINES = ("10.20.0.10", "10.20.0.11", "10.20.0.12")
ALLOWED_PORTS = {"22", "8443", "9000", "9100"}


def read(name):
    return (HERE / name).read_text(encoding="utf-8")


def without_comments(text):
    return "\n".join(re.sub(r"\s//.*$|^\s*#.*$", "", line) for line in text.splitlines())


def bicep_rules(text):
    """The security rules of the Bicep firewall, as dicts of the fields the invariants look at."""
    body = text.split("securityRules: [", 1)[1].split("\nresource vnet", 1)[0]
    rules = []
    for chunk in re.split(r"\n\s*name: '", body)[1:]:
        rule = {"name": chunk.split("'", 1)[0]}
        for key in ("priority", "access", "protocol", "sourceAddressPrefix", "destinationAddressPrefix",
                    "destinationPortRange", "direction"):
            m = re.search(key + r": ([^\n]+)", chunk)
            rule[key] = m.group(1).strip().strip("'") if m else None
        rules.append(rule)
    return rules


class Bicep(unittest.TestCase):
    text = without_comments(read("azure.bicep"))

    def test_only_the_planned_flows_are_allowed(self):
        allows = [r for r in bicep_rules(self.text) if r["access"] == "Allow"]
        self.assertEqual({r["destinationPortRange"] for r in allows}, {"22", "8443", "9000", "9100"})
        for r in allows:
            self.assertEqual(r["direction"], "Inbound", r["name"])
            self.assertEqual(r["protocol"], "Tcp", r["name"])
            if r["destinationPortRange"] == "22":
                self.assertEqual(r["sourceAddressPrefix"], "${adminIp}/32", "ssh only from the one address given")
            else:
                self.assertEqual(r["sourceAddressPrefix"], "subnetPrefix", f"{r['name']}: between the machines only")

    def test_everything_else_is_denied_before_azure_default_allow(self):
        rules = bicep_rules(self.text)
        deny = [r for r in rules if r["access"] == "Deny"]
        self.assertEqual(len(deny), 1)
        d = deny[0]
        self.assertEqual((d["sourceAddressPrefix"], d["destinationPortRange"], d["protocol"]), ("*", "*", "*"))
        self.assertLess(int(d["priority"]), 65000, "must come before Azure's default AllowVnetInBound (65000)")
        for r in rules:
            if r["access"] == "Allow":
                self.assertLess(int(r["priority"]), int(d["priority"]), r["name"])

    def test_nothing_is_open_to_the_internet(self):
        self.assertNotIn("0.0.0.0/0", self.text)
        self.assertNotIn("'Internet'", self.text)

    def test_ssh_by_key_only(self):
        self.assertIn("disablePasswordAuthentication: true", self.text)
        self.assertNotIn("adminPassword", self.text)

    def test_address_plan(self):
        for ip in MACHINES:
            self.assertIn(f"ip: '{ip}'", self.text)
        self.assertIn("subnetPrefix = '10.20.0.0/24'", self.text)

    def test_login_and_image(self):
        self.assertIn("param adminUsername string = 'tbp'", self.text)
        self.assertIn("offer: 'debian-12'", self.text)


class Cloudformation(unittest.TestCase):
    raw = read("aws.cfn.yaml")
    text = without_comments(raw)

    def test_ssh_rule_is_the_only_inline_ingress(self):
        inline = self.text.split("SecurityGroupIngress:", 1)[1].split("Tags:", 1)[0]
        self.assertEqual(re.findall(r"FromPort: (\d+)", inline), ["22"])
        self.assertEqual(re.findall(r"CidrIp: (.+)", inline), ["!Sub '${AdminIp}/32'"])

    def test_other_ingress_rules_are_the_three_ports_from_the_group_itself(self):
        rules = re.findall(r"Type: AWS::EC2::SecurityGroupIngress\n    Properties:\n(.*?)\n\n", self.text, re.S)
        self.assertEqual(len(rules), 3)
        ports = set()
        for r in rules:
            self.assertIn("SourceSecurityGroupId: !Ref Firewall", r)
            self.assertNotIn("CidrIp", r)
            ports.add(re.search(r"FromPort: (\d+)", r).group(1))
            self.assertEqual(re.search(r"FromPort: (\d+)", r).group(1), re.search(r"ToPort: (\d+)", r).group(1))
        self.assertEqual(ports, {"8443", "9000", "9100"})

    def test_the_only_open_cidr_is_the_default_route(self):
        lines = [l for l in self.text.splitlines() if "0.0.0.0/0" in l]
        self.assertEqual(len(lines), 1)
        self.assertIn("DestinationCidrBlock", lines[0])

    def test_admin_address_is_one_ipv4_address(self):
        pattern = re.search(r"AllowedPattern: '(.+)'", self.text).group(1)
        for good in ("203.0.113.7", "78.1.2.3", "255.255.255.255"):
            self.assertRegex(good, pattern)
        for bad in ("", "0.0.0.0/0", "203.0.113.0/24", "203.0.113.7/32", "203.0.113", "256.1.1.1", "a.b.c.d",
                    "203.0.113.7 ", "1.2.3.4,5.6.7.8"):
            self.assertNotRegex(bad, pattern)

    def test_address_plan_and_disks(self):
        for ip in MACHINES:
            self.assertEqual(self.text.count(f"PrivateIpAddress: {ip}"), 1)
        self.assertEqual(self.text.count("Encrypted: true"), 3)
        self.assertNotIn("IamInstanceProfile", self.text)
        self.assertNotIn("UserData", self.text)

    def test_image_is_debian_12(self):
        self.assertIn("/aws/service/debian/release/12/latest/amd64", self.text)


class Guides(unittest.TestCase):
    def test_every_guide_names_the_address_plan_and_the_ports(self):
        for name in ("README.md", "README.fr.md"):
            text = read(name)
            for token in (*MACHINES, "8443", "9000", "9100", "22"):
                self.assertIn(token, text, f"{name} must mention {token}")

    def test_logins_match_the_templates(self):
        self.assertIn("tbp@", read("azure.md"))
        self.assertIn("tbp@", read("azure.fr.md"))
        self.assertIn("admin@", read("aws.md"))
        self.assertIn("admin@", read("aws.fr.md"))

    def test_guides_begin_with_a_validation_that_creates_nothing(self):
        for name in ("azure.md", "azure.fr.md"):
            self.assertIn("az deployment group validate", read(name))
        for name in ("aws.md", "aws.fr.md"):
            self.assertIn("aws cloudformation validate-template", read(name))

    def test_guides_say_which_template_was_run_for_real(self):
        """Honesty about what was tested: Azure once, by the maintainer; AWS never, until someone does."""
        self.assertIn("**The AWS template has not been run\nagainst a real account**", read("README.md"))
        self.assertIn("**Le modèle AWS n'a pas été exécuté sur un vrai compte**", read("README.fr.md"))
        self.assertIn("**The Azure template has been\ndeployed once for real**", read("README.md"))

    def test_the_cell_machine_is_told_to_install_a_c_compiler(self):
        """brokerd links C code: without gcc the build fails far from the cause (first Azure deployment)."""
        dev = HERE.parent
        for name in ("site.md", "site.fr.md", "solo.md", "solo.fr.md"):
            text = (dev / name).read_text(encoding="utf-8")
            line = next(l for l in text.splitlines() if "apt-get install -y git curl jq openssl" in l)
            self.assertIn("gcc libc6-dev", line, f"{name}: the packages of the machine that builds the cell")
        for name in ("site.sh", "devtest.sh"):
            text = (dev.parent.parent / "scripts" / "devtest" / name).read_text(encoding="utf-8")
            self.assertIn('[ "$b" != brokerd ] || need gcc "brokerd links C code: sudo apt-get install -y gcc libc6-dev"',
                          text, f"{name} must fail early, with the cure, when there is no C compiler")

    def test_deallocate_not_stop(self):
        for name in ("azure.md", "azure.fr.md"):
            self.assertIn("az vm deallocate", read(name))

    def test_no_personal_address_in_the_repository(self):
        """The guides use placeholders; an actual public address of a tester must never be committed."""
        for p in HERE.iterdir():
            if p.suffix in {".md", ".bicep", ".yaml", ".py"} and p.name != "test_templates.py":
                for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", p.read_text(encoding="utf-8")):
                    self.assertTrue(ip.startswith(("10.20.0.", "203.0.113.", "0.0.0.0", "255.255", "127.", "169.254")) or ip in {"168.63.129.16"},
                                    f"{p.name}: unexpected address {ip}")


if __name__ == "__main__":
    unittest.main()
