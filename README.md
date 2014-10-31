<H1>GDS Anti-CSRF Library</H1>
**Authors:** Erik Larsson (elarsson@gdssecurity.com), Ron Gutierrez (rgutierrez@gdssecurity.com)<BR>
**Company:** Gotham Digital Science, LLC<BR>

This library is designed to be a secure and flexible solution for protecting J2EE web applications against Cross-Site Request Forgery (CSRF) exposures. The solution was initially derived from the anti-CSRF protection built into the SendSafely platform and the specific requirements of a leading financial institution looking to deploy a common, firm-wide solution to CSRF prevention. Open source alternatives were investigated, and while each had its pros and cons and could have potentially worked in a specific instance, none of them was flexible enough to adapt to the diverse and evolving web technology stack of our financial services partner. Since the initial design and implementation, development has continued and the library has undergone several enterprise integrations. 

The following is a list of requirements and guidelines that governed the initial design and implementation of the GDS Anti-CSRF library. Although the implementation is specific to Java/J2EE web application architectures, these requirements and guidelines have been generalized to the extent possible. The intention is to provide developers of other common web technologies a foundation for developing an Anti-CSRF solution with equivalent security and integration flexibility.<BR>

**1.	CSRF Protection Must Support Stateless and Stateful Modes**<BR>
The solution must work with web applications that do and do not utilize session storage. 

**2.	CSRF Token Life Must Be Configurable**<BR>
Token life options supported by Stateless and Stateful modes must be configurable.  

**3.	CSRF Token Protection Scope Must Be Configurable**<BR>
It must be possible to configure the following:
<ul>
<li>White list of exempt URLs - By default, a non-expired token will be considered valid for all application requests (i.e. site-wide protection). It must be possible to exempt specific URLs from site-wide CSRF token validation.</li>

<li>Black list of protected URLs – it must be possible to only protect specific URLs with a CSRF token</li>
</ul>

**4.	API and Integration Documentation Must Be Provided**<BR>
The solution API and integration steps must be clearly documented.

**5.	CSRF Tokens Should be User Specific**<BR> 
The CSRF token should be tied to the authenticated user’s identity. 

**6.	CSRF Token Protection Scope Should Support Form Specific Protection**<BR>
The scope of protection can be configured so that a non-expired token is tied to a specific form. 

Note: This requirement was initially out of scope however the feature is on the roadmap for a future version. 

**7.	Simple Integration with Existing Web Application Technology Stack**<BR> 
The solution should adhere to the following principles to ensure it is as plug-n-play as possible: 

<ul>
<li>Designed as a library that can be referenced by existing applications</li>
<li>Utilize core platform-level APIs and specifications</li> 
<li>Minimize use of 3rd party libraries</li> 
<li>Aim to limit code modifications to source code of the integrating application</li>
</ul>

Refer to the <a href="https://github.com/GDSSecurity/SS_OSS_Anti-CSRF_Solution/wiki">Wiki</a> for complete documentation and setup instructions.

The GDS Anti-CSRF Library is provided under GNU GPL v3.0 (http://www.gnu.org/licenses/gpl.html) or any later version<BR>
Copyright (c) 2014 Gotham Digital Science, LLC -- All Rights Reserved
