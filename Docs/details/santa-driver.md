# santa-driver

santa-driver is a macOS [kernel extension](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KEXTConcept/KEXTConceptIntro/introduction.html) (KEXT) that makes use of the [Kernel Authorization](https://developer.apple.com/library/content/technotes/tn2127/_index.html) (Kauth) KPI. This allows santa-driver to listen for events and either deny or defer the decision of those events. The overall architecture of santa-driver is fairly straightforward. It basically acts as an intermediary layer between Kauth and santad, with some caching to lower the overhead of decision making.

##### Kauth

santa-driver `KAUTH_SCOPE_VNODE` and `KAUTH_SCOPE_FILEOP `

##### Driver Interface



##### Cache

