The following list highlights key areas where the GDS solution could improve through community contributions. A priority and estimated effort to complete has been supplied.<BR>

**Update documentation to include all possible configuration options (High, Medium)**<BR>

**Add more code samples / tutorials to documentation (High, Medium)**<BR>

**Add more test cases for recent code additions, such as removal of J2EE dependency (High, Medium)**<BR>

**Inject tokens automatically at runtime (High, High)**<BR>
The library should offer the capability to automatically insert tokens at runtime (similar to OWASP CSRFGuard). Both traditional HTML based requests as well as AJAX Post requests must be included. Implementing an automated solution would simplify the integration significantly. Runtime injection can however be dangerous since it might introduce an unpredictable behavior in the application where incorrect functionality is not detected until a runtime exception is raised. It might also break hyperlinks if GET requests are being protected.

**Add form specific protection to Token Protection Scope (High, TBD)**<BR>

**Integrate FindBugs and Fortify into build script (Medium, Low)**<BR>

**Add Maven Integration (Medium, Low)**<BR>
All other Java implementations offer automated build integration using Maven. Integrating Maven into the GDS library would make it easier to integrate the library and its dependencies. Bigger projects tend to use automated solutions to keep track of dependencies and Maven is the most common solution to accomplish this. Using Maven would simplify the integration for many application owners.

**Implement Customizable Logging (Medium, Medium)**<BR>
In order to better adopt to custom applications the logging can be made more flexible. One identified action is to implement support for SLF4J.

SLF4J is an abstraction framework supporting various popular logging APIs such as Log4J or java.util.Logging. Implementing SLF4J will allow the implementing application to decide what logging utility the CSRF library should use. The current solution will use java.util.Logging and any application that wants to use the CSRF logs is therefore forced to use that logging utility. SLF4J would remove that dependency.

**Implement Double Cookie Submit Pattern (Low, Medium)**<BR>

**Build a tool to help developers identify all requests that might need CSRF Protections (TBD)**<BR>
A tool to help developers identify potential CSRF vulnerabilities could be built alongside the CSRF library. The tool could point out locations where CSRF protection is missing and thereby simplify the manual integration. A development team would have to run the tool and manually add token protection based on the results. Although it forces some manual integration, pointing out where and what code to protect will make the integration faster. The tool would use a similar approach to the runtime injection and look for requests being sent to the server. The tool could be built using known frameworks such as PMD and be integrated into the build procedure. Development teams would in such a solution get an update of the current state of the CSRF protection regularly.
