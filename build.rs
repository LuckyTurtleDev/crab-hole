fn main() {
	// Enable "nightly" cfg if the current compiler is nightly.
	if rustc_version::version_meta().unwrap().channel == rustc_version::Channel::Nightly {
		println!("cargo:rustc-cfg=nightly");
	}
}
