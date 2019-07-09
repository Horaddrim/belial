# Belial

Belial is one of the [Lesser evils](https://diablo.fandom.com/wiki/Lesser_Evils) of the [Burning Hells](https://diablo.fandom.com/wiki/Burning_Hells)
Responsible for the Realm of Lies, he is known by the title of Lord of Lies.
[Show your love and support for Diablo](https://diablo.fandom.com/wiki/Diablo_Wiki)

## The tool
The tool is aimed to help and execute the well-known [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) network attack, by giving the network analyst the power for passively monitor the packages flying in the network, and also actively asking for ARP packages to map the network. And since it's a security tool, it also forges a custom package with customized fields so the analyst can test the resistance of the network setup against this kind of attacks.

## Usage and installation
Nowadays Belial can only be compiled from source, but you can easily download and build it since you have the Go toolchain that you can get for free at the [languages official website](https://golang.org/dl/).

**WARNING: Windows users, sorry, as far as I know, Windows does not allow writing packages from the kernel's userspace so I don't think this tool will work for you :sparkling_heart:**

After getting the `go` tool, you can enter in your favorite terminal the following:
 - `go get github.com/horaddrim/belial` which will download the source code in your `$GOPATH`
 		Note: This will download the source code usually to the `$HOME/go/src/github.com/horaddrim/belial` folder unless your specific configurations say otherwise.
 	- After getting the source code you can go ahead, enter the folder and enter the command `go build -o Belial`, this will produce a binary named `belial` in your current folder.
 	- No matter where you built the application, after generating the binary move it to the `$HOME/go/bin/` folder (in the default Golang workspace configuration), and if you want to access the tool from pretty much anywhere you want, add the `go/bin` folder to your `$PATH` so you can always have instantly Go-based tools in your terminal.

Congrats :D Is time for some fun :smilling_imp:

After having the tool installed and available, you can go ahead and see the `help` command output, and get an overview of the current capabilities of your new little network imp.

## Bugs, feedback and/or improvements
Please leave an issue in the [Issues](https://github.com/horaddrim/belial/issues/new) section, so I can keep track of everything and also report status about it! And feel free to send PRs/ documentation contributions to make the tool more user-friendly for the next generation of network enthusiasts!

## License
This project is licensed under the Apache License v2.0, see the [LICENSE](https://github.com/horaddrim/belial/blob/master/LICENSE) file for details, or [reach me out](mailto:lee12rock@gmail.com) for copyright and/or any question about it.

## Roadmap
**This still in alpha release, so we are currently only supporting scanning the interface, but I pretend to add (obviously) the forging feature**

 - [ ] Lua support for custom scripting around ARP packages
 - [ ] Support for reading/writing `.pcapng` files
 - Maybe a GUI? (I like a CLI, but will guys who rules <3)
 