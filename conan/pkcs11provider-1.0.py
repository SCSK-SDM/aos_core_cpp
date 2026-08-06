from conan import ConanFile
from conan.tools.meson import MesonToolchain, Meson
from conan.tools.scm import Git
from conan.tools.layout import basic_layout
from conan.tools.env import VirtualBuildEnv
from conan.tools.gnu import PkgConfigDeps

class PKCS11Provider(ConanFile):
    name = "pkcs11provider"
    branch = "main"
    # The v1.0 tag prompts for a PIN interactively instead of honouring the
    # pin-source parameter of a PKCS#11 URI, so TLS handshakes fail in daemons:
    #   Enter PIN for PKCS#11 Token (Slot ...):
    #   Handshake failed with fatal error SSL_ERROR_SSL: UI routines::processing error
    # Use the same revision meta-aos ships (recipes-connectivity/pkcs11-provider_1.0.bb),
    # which is a later commit on main and reads the PIN from pin-source.
    revision = "8f6b94409d4872265076df310492da1e5f6abdf7"
    version = "1.0"
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires("openssl/3.2.1")

    def configure(self):
        self.options["openssl"].shared = True

    def build_requirements(self):
        self.build_requires("meson/0.64.1")

    def layout(self):
        basic_layout(self)

    def source(self):
        git = Git(self)
        clone_args = ['--branch', self.branch]
        git.clone("https://github.com/latchset/pkcs11-provider.git", args=clone_args, target=self.source_folder)
        git.checkout(self.revision)

    def generate(self):
        env = VirtualBuildEnv(self)
        env.generate()

        deps = PkgConfigDeps(self)
        deps.generate()

        tc = MesonToolchain(self)
        tc.generate()

    def build(self):
        meson = Meson(self)
        meson.configure()
        meson.build()

    def package(self):
        meson = Meson(self)
        meson.install()
