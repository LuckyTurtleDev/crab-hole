use rustc_version::Version;

fn main() {
	let version_meta = rustc_version::version_meta().unwrap();
	// Enable "nightly" cfg if the current compiler is nightly.
	if version_meta.channel == rustc_version::Channel::Nightly {
		println!("cargo:rustc-cfg=nightly");
	}
	// Enable check-cfg for "nightly" config for rust >=1.79 where the lint was added
	if version_meta.semver >= Version::new(1, 79, 0) {
		println!("cargo::rustc-check-cfg=cfg(nightly)");
	}
}
