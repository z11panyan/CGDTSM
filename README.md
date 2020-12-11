# CGDTSM
CGDTSM, whose fullname is Coverage-guided Differential Testing with Syntax-based Mutation
It is a hybrid tool based on Nezha-dt and TLS-diff
CGDTSM exploits the behavioral asymmetries between multiple test programs to focus on inputs that
are more likely to trigger logic bugs.

# Getting Started
The current code is running in the environment of llvm9 and clang9
Users can start with the examples of nezha [v-0.1](https://github.com/nezha-dt/nezha/tree/v0.1).
Then, you can better comprehend the example about "handshake"

Before you run the makefile of the dir "handshake", you should make the certain version of SSL implements with clang and sanitizercoverage



# Support
We welcome issues and pull requests with new fuzzing targets.
