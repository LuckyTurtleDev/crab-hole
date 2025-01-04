fn main() {
	let version_meta = rustc_version::version_meta().unwrap();
	// Enable "nightly" cfg if the current compiler is nightly.
	if version_meta.channel == rustc_version::Channel::Nightly {
		println!("cargo:rustc-cfg=nightly");
	}
}
