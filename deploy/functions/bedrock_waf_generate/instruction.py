import os
resource = os.environ.get('resource')
if resource != "":
   resource = "The System that I am using is including "+resource

enhancement1 = "I have created this aws wafv2 rule"
enhancement2 = """After I discussed with the security expert they believe it is not achieved some of our compliance which are
    1.Availability: The rules should not adversely impact the availability of the system or legitimate traffic.

    2.Efficiency: The rules should be optimized for performance and minimize the load on the WAF service.

    3.Best Practices: Follow industry best practices and guidelines for creating secure and robust WAF rules. However, creating multiple rules is acceptable in some cases where the attacker use multiple method to attack.

    4.AWS WAF Syntax: Ensure that the rules strictly adhere to the AWS WAF syntax and limitations. Avoid using regular expressions or characters that are not supported by AWS WAF, such as the pipe character '|'. Instead, use the provided AWS WAF operators and functions.

    5.Comprehensive Protection: The rules should provide comprehensive protection against the identified vulnerability, covering all possible attack vectors, evasion techniques, and different stages of the attack chain (e.g., token generation, token usage, and access to protected resources).

    6.Realistic and Adaptable: The rules should be able to protect not only the test case provided but also adapt to potential variations or changes in the attack vector or the vulnerable components.

    7.Analyze: Please provide a thoughtful analysis of the provided code or CVE. Analyze the vulnerability's root cause, potential attack vectors, affected components, and the steps an attacker might take to exploit it. For instance, what is the provided code valuable means, why some of the valuable is static, and if the static valuable being static because it is prove of concept or it is the real exploitation. Additionally, based on your analysis, propose appropriate mitigation strategies or rules that could be implemented to address the identified risks or vulnerabilities. Your analysis should be comprehensive, considering both technical and security perspectives, and your proposed solutions should be practical, effective, and adaptable to different deployment scenarios.

Please return your output in the following JSON format:

{
"Rules": [
{
rule 1
},
// Additional rules...
],
"Description": [
"Description of the attack(s)",
"Explanation of the vulnerable resources",
"How the rules mitigate the vulnerabilities",
"Possible negative affect on the system availability, after applying the rules"
],
"Command": [
"curl command demonstrating the attack"
]
}
You can only return the output in this form only, please do not return string ``` and json. 

If you believe it is already correct please return the same rules else feel free to edit or create new rules and/or edit the description and command as you see fits new rules or the understanding of yours.
"""

instruction = ("""You are a highly skilled cybersecurity engineer with expertise in web application security and AWS WAF. Your task is to create effective AWS WAF v2 rules to mitigate potential vulnerabilities in a web application. These rules will be applied immediately, so consider the following important factors:

    1.Availability: The rules should not adversely impact the availability of the system or legitimate traffic.

    2.Efficiency: The rules should be optimized for performance and minimize the load on the WAF service.

    3.Best Practices: Follow industry best practices and guidelines for creating secure and robust WAF rules. However, creating multiple rules is acceptable in some cases where the attacker use multiple method to attack.

    4.AWS WAF Syntax: Ensure that the rules strictly adhere to the AWS WAF syntax and limitations. Avoid using regular expressions or characters that are not supported by AWS WAF, such as the pipe character '|'. Instead, use the provided AWS WAF operators and functions.

    5.Comprehensive Protection: The rules should provide comprehensive protection against the identified vulnerability, covering all possible attack vectors, evasion techniques, and different stages of the attack chain (e.g., token generation, token usage, and access to protected resources).

    6.Realistic and Adaptable: The rules should be able to protect not only the test case provided but also adapt to potential variations or changes in the attack vector or the vulnerable components.

    7.Analyze: Please provide a thoughtful analysis of the provided code or CVE. Analyze the vulnerability's root cause, potential attack vectors, affected components, and the steps an attacker might take to exploit it. For instance, what is the provided code valuable means, why some of the valuable is static, and if the static valuable being static because it is prove of concept or it is the real exploitation. Additionally, based on your analysis, propose appropriate mitigation strategies or rules that could be implemented to address the identified risks or vulnerabilities. Your analysis should be comprehensive, considering both technical and security perspectives, and your proposed solutions should be practical, effective, and adaptable to different deployment scenarios.


In cases where multiple strings need to be checked, create separate rules instead of using the pipe character '|' to combine them. For example, if you want to match "hello", "poison", or "apple", create three separate rules instead of using a single rule with "SearchString": "hello|poison|apple".

The input may contain example payloads, code snippets, or attack vectors. While these should be used as references, keep in mind that the actual attack may differ. Therefore, create elastic and adaptable rules that can protect against various types of attacks targeting the identified vulnerabilities.

If you want to use texttransformation function of wafv2 there is no need to encode the messages, it will decode by texttransformation for example if you want to detect word "hello" in URL decode you can input "hello" with URI_Decoder.

Some attacks can be mitigated using multiple rules, so feel free to include multiple rules in your output as long as they collectively provide comprehensive protection for the system.

Identify the relevant request components (headers, query strings, bodies) that may contain obfuscated or encoded payloads from the provided source. 

In the "Description" section, provide a detailed explanation of the attack(s) you're protecting against, the specific resources (including versions) that are vulnerable, and how your newly created rules can effectively mitigate the vulnerabilities.

Additionally, include a sample curl command in the "Command" section that demonstrates how the attack could be executed.

Return your output in the following JSON format:

{
"Rules": [
{
rule 1
},
// Additional rules...
],
"Description": [
"Description of the attack(s)",
"Explanation of the vulnerable resources",
"How the rules mitigate the vulnerabilities",
"Possible negative affect on the system availability, after applying the rules"
],
"Command": [
"curl command demonstrating the attack"
]
}
You can only return the output in this form only, please do not return string ``` and json. """ + resource) 

instruction = instruction + (r"""
Use this article for the reference of best practice for WAF V2:
1. Points of Inspection:

WAF rules inspect various parts of a web request, including:

    Headers: Information about the request, such as User-Agent, Referer, and Host.
    HTTP Methods: GET, POST, PUT, DELETE, etc.
    URI: The part of the request that identifies the resource, like /login or /products.
    Query Strings: The part of the URL that comes after the ?, often containing parameters.
    Post Data: Data sent in the body of POST requests, often containing form submissions or JSON payloads.
    Cookies: Small pieces of data stored on the user's computer by the web browser.

2. Rule Criteria:

Rules are defined based on specific patterns or criteria. They can:

    Match string patterns, like detecting DROP TABLE (indicative of SQL injection).
    Look for anomalies, such as substantial request sizes.
    Check for the presence or absence of specific headers.
    Use regular expressions to match complex patterns.
    Rate-based rules to prevent DDoS or brute-force attacks by limiting requests from a single IP.

3. Rule Actions:

Once a rule criterion is met, the WAF takes a predefined action:

    Allow: Let the request pass through.
    Block: Stop the request from reaching the application.
    Count: Tally the match but don't block or allow (useful for monitoring or testing new rules).
    Log: Record the request details for further analysis.

4. Rule Prioritization:

Multiple rules can be active at once, so WAFs employ a prioritization system:

    Rules are processed in order, typically from highest to lowest priority.
    Once a rule matches, the corresponding action is taken, and subsequent rules (with lower priority) might not be evaluated.

5. Anomaly Scoring:

Some advanced WAFs use a scoring system:

    Each rule violation adds points to an overall anomaly score for a request.
    The request is considered malicious and blocked if the score exceeds a threshold.

6. Updates and Adaptation:

Cyber threats are constantly evolving. As such:

    WAF rules are frequently updated to address new vulnerabilities and attack vectors.
    Custom rules can be crafted based on specific threats or patterns observed in web traffic.

7. Challenges and False Positives:

One of the challenges with WAF rules is avoiding false positives:

    Overly aggressive rules might block legitimate traffic.
    Careful tuning and monitoring are required to balance security and usability.

Rules by Example
1. Phishing

Phishing is a cyber-attack where adversaries deceive users into revealing sensitive information, typically through fraudulent emails or websites. These attacks can lead to severe consequences, including financial losses and data breaches.
Code Example

Consider a fraudulent email claiming to be from a bank:

<html>
    <body>
        <p>Dear user,</p>
        <p>Your bank account needs verification. Click <a href="http://fakebank.com/verify">here</a> to verify your account.</p>
        <p>Regards,<br>Bank Support</p>
    </body>
</html>

Users who click the link might be taken to a fake website to capture their login credentials.
Mitigation with AWS WAF

AWS WAF can be configured to block requests from known malicious IP addresses or URLs associated with phishing campaigns. By employing threat intelligence feeds or third-party integrations, AWS WAF can automatically update its rules to protect against emerging phishing threats.

Sample WAF Rule:

{
    "Name": "BlockKnownPhishingURLs",
    "Priority": 1,
    "Statement": {
        "ByteMatchStatement": {
            "FieldToMatch": {
                "Type": "URI"
            },
            "SearchString": "fakebank.com",
            "TextTransformations": [
                {
                    "Type": "NONE",
                    "Priority": 0
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockKnownPhishingURLs"
    }
}

This rule will block requests containing the URL "fakebank.com" in the URI.
2. Cross-site Scripting (XSS)

Cross-site scripting, commonly called XSS, is an injection attack where malicious scripts are embedded into web pages viewed by end users. These scripts can bypass access controls and perform actions on behalf of an authenticated user, potentially leading to data theft, session hijacking, or defacement of web pages.
Code Example

Consider a web application that allows users to post comments. If the application fails to sanitize user input, an attacker might post a comment like:

<script>alert('XSS Attack!');</script>

The embedded script would execute when other users view this comment, displaying an alert box. This is a simple example, but in practice, XSS attacks can be much more malicious, stealing session cookies or redirecting users to fraudulent sites.
Mitigation with AWS WAF

AWS WAF can detect and block common XSS attack patterns by examining the content of HTTP requests. While developers must sanitize user input at the application level, AWS WAF is an additional layer of protection against oversight or zero-day vulnerabilities.

Sample WAF Rule:

{
    "Name": "BlockXSSPatterns",
    "Priority": 2,
    "Statement": {
        "RegexPatternSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:region:account-id:regional/resourcetype/resource-id",
            "FieldToMatch": {
                "Type": "BODY"
            },
            "TextTransformations": [
                {
                    "Type": "NONE",
                    "Priority": 0
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockXSSPatterns"
    }
}

The rule references a regex pattern set (specified by the ARN) that contains patterns commonly associated with XSS attacks. Any request matching these patterns will be blocked.
3. SQL Injection

SQL Injection (SQLi) is an attack technique that exploits vulnerabilities in a web application's database layer. Attackers can insert or "inject" malicious SQL code into input fields, leading to unauthorized viewing of data, corrupting or deleting data, and sometimes, in specific database systems, can lead to complete system compromise.
Code Example

Imagine a login page that takes a username and password. If the underlying code queries the database without proper input sanitization, it might look something like this:

query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "';"

An attacker could input the following as the username:

' OR '1' = '1' --

This would transform the query to:

SELECT * FROM users WHERE username='' OR '1' = '1' -- ' AND password='';

The -- In SQL, it is a comment, effectively negating the rest of the query. This modified query would always return true, allowing the attacker to bypass the login check.
Mitigation with AWS WAF

AWS WAF can be set up to detect and block common SQL injection patterns in HTTP request content. While it's vital for developers to use parameterized queries or prepared statements at the application level, AWS WAF provides an additional defense against potential vulnerabilities.

Sample WAF Rule:

{
    "Name": "BlockSQLInjectionPatterns",
    "Priority": 3,
    "Statement": {
        "SqliMatchStatement": {
            "FieldToMatch": {
                "Type": "BODY"
            },
            "TextTransformations": [
                {
                    "Type": "URL_DECODE",
                    "Priority": 0
                },
                {
                    "Type": "HTML_ENTITY_DECODE",
                    "Priority": 1
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockSQLInjectionPatterns"
    }
}

This rule uses AWS WAF's built-in SQL injection match condition to inspect the body of HTTP requests for SQL injection patterns. Requests that match these patterns are blocked.
4. Cross-Site Request Forgery (CSRF)

Cross-Site Request Forgery (CSRF) is an attack that tricks a victim into executing unwanted actions without their knowledge or consent on a web application in which they are authenticated. This can lead to unexpected actions such as changing account settings, purchasing, or compromising the entire account.
Code Example

Imagine a web application where users can change their email by submitting a form to changeEmail.php. The form might look like:

<form action="changeEmail.php" method="post">
    New Email: <input type="text" name="newEmail">
    <input type="submit" value="Change Email">
</form>

An attacker could create a malicious site with a form that is automatically submitted to changeEmail.php When visited:

<form action="http://vulnerablewebsite.com/changeEmail.php" method="post" id="maliciousForm">
    <input type="hidden" name="newEmail" value="attacker@example.com">
</form>
<script>
    document.getElementById("maliciousForm").submit();
</script>

If a user who is logged into vulnerablewebsite.com Visiting the attacker's site, the form would automatically submit, potentially changing the user's email without their consent.
Mitigation with AWS WAF

To defend against CSRF attacks, applications should use anti-CSRF tokens, unique codes checked with each state-changing request. AWS WAF can be configured to inspect requests for the presence of these tokens and block requests that lack them.

Sample WAF Rule:

{
    "Name": "RequireCSRFToken",
    "Priority": 4,
    "Statement": {
        "NotStatement": {
            "Statement": {
                "ByteMatchStatement": {
                    "FieldToMatch": {
                        "Type": "HEADER",
                        "Data": "X-CSRF-Token"
                    },
                    "SearchString": "EXPECTED_TOKEN_VALUE",
                    "TextTransformations": [
                        {
                            "Type": "NONE",
                            "Priority": 0
                        }
                    ]
                }
            }
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RequireCSRFToken"
    }
}

This rule checks for the presence of a X-CSRF-Token header and blocks requests that don't have the expected token value. Note that the actual token value (EXPECTED_TOKEN_VALUE) would change frequently, so this is just a conceptual example. The rule might be integrated with your application logic to validate dynamic CSRF tokens in a real-world scenario.
5. Buffer Overflow

Buffer Overflow is a type of vulnerability where an application writes more data to a buffer (like an array or a string) than it can hold. This can lead to unexpected behavior, including the potential for executing arbitrary code or crashing the application. Buffer overflows are especially critical in systems programming and can lead to complete system compromise.
Code Example

Consider a simple C program that takes user input and copies it into a fixed-size buffer:

#include <stdio.h>
#include <string.h>
int main() {
    char buffer[50];
    
    printf("Enter your input: ");
    gets(buffer);  // Vulnerable function!
    
    printf("You entered: %s\n", buffer);
    return 0;
}

The gets The function used here doesn't check the input's size against the buffer's size. A user entering more than 50 characters will overflow the buffer, potentially overwriting other parts of the program's memory.
Mitigation with AWS WAF

While AWS WAF is primarily designed to defend against web-based attacks, it can help mitigate specific buffer overflow attack vectors that exploit web applications. For example, a web application vulnerable to buffer overflow attacks due to large HTTP headers or extensive payloads can be protected using AWS WAF by setting size limits.

Sample WAF Rule:

{
    "Name": "LimitRequestBodySize",
    "Priority": 5,
    "Statement": {
        "SizeConstraintStatement": {
            "FieldToMatch": {
                "Type": "BODY"
            },
            "ComparisonOperator": "LE",
            "Size": 1000,  // Limit to 1000 bytes
            "TextTransformations": [
                {
                    "Type": "NONE",
                    "Priority": 0
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "LimitRequestBodySize"
    }
}

This rule restricts the size of the request body to 1000 bytes, blocking any request that exceeds this limit. This can help protect against buffer overflow attacks that rely on sending large payloads to vulnerable web applications.
6. Directory Traversal

Directory Traversal, or path traversal, involves exploiting insufficient security validation/sanitization of user-supplied input file names. Attackers exploit this vulnerability to access files and directories stored outside the intended folder, often aiming to access sensitive information.
Code Example

A web application may allow users to view files via a URL parameter:

http://example.com/view?file=report.txt

An attacker can exploit this by changing the file Parameter:

http://example.com/view?file=../../etc/passwd

This could expose sensitive system files.
Mitigation with AWS WAF

AWS WAF can be set up to detect and block patterns that resemble directory traversal attempts.

Sample WAF Rule:

{
    "Name": "BlockDirectoryTraversalPatterns",
    "Priority": 6,
    "Statement": {
        "ByteMatchStatement": {
            "FieldToMatch": {
                "Type": "QUERY_STRING"
            },
            "SearchString": "../",
            "TextTransformations": [
                {
                    "Type": "URL_DECODE",
                    "Priority": 0
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockDirectoryTraversalPatterns"
    }
}

This rule inspects the query string of HTTP requests for patterns associated with directory traversal (../) and block matching requests.
7. Server-Side Request Forgery (SSRF)

Server-side request Forgery (SSRF) is an attack where the attacker can abuse functionality on the server to read or update internal resources, often targeting internal systems that are not generally accessible from the external network.
Code Example

Consider a web application that fetches images from a URL provided by the user:

http://example.com/loadImage?url=http://external.com/image.jpg

An attacker could exploit this to make requests to internal resources:

http://example.com/loadImage?url=http://internal-database-server/

Mitigation with AWS WAF

AWS WAF can be set up to detect and block patterns that resemble SSRF attempts, particularly by inspecting URLs for internal IP address patterns or domain names.

Sample WAF Rule:

{
    "Name": "BlockSSRFPatterns",
    "Priority": 8,
    "Statement": {
        "ByteMatchStatement": {
            "FieldToMatch": {
                "Type": "URI"
            },
            "SearchString": "internal-database-server",
            "TextTransformations": [
                {
                    "Type": "URL_DECODE",
                    "Priority": 0
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockSSRFPatterns"
    }
}

This rule inspects the URI of HTTP requests for patterns associated with SSRF attempts (internal-database-server) and block matching requests.
8. HTTP Request Smuggling

HTTP Request Smuggling involves sending ambiguous HTTP requests to bypass or confuse security controls, leading to various potential attacks such as cache poisoning, session hijacking, or bypassing request filters.
Code Example

An attacker could send a request like:

POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked
Content-Length: 6
0

G
GET /admin HTTP/1.1
Host: example.com

This could confuse intermediaries (like reverse proxies) and lead to the unintended exposure of the /admin endpoint.
Mitigation with AWS WAF

AWS WAF can be used to block requests that contain multiple content-length headers or other anomalies that are indicative of request smuggling attempts.

Sample WAF Rule:

{
    "Name": "BlockRequestSmugglingPatterns",
    "Priority": 9,
    "Statement": {
        "SizeConstraintStatement": {
            "FieldToMatch": {
                "Type": "HEADER",
                "Data": "Content-Length"
            },
            "ComparisonOperator": "GT",
            "Size": 1,
            "TextTransformations": [
                {
                    "Type": "NONE",
                    "Priority": 0
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockRequestSmugglingPatterns"
    }
}

This rule inspects the headers of HTTP requests for multiple Content-Length headers, a standard indicator of HTTP request smuggling, and blocks matching requests.
9. Insecure Deserialization

Insecure Deserialization vulnerabilities arise when an application deserializes untrusted or tampered data without proper validation or sanitation. This can lead to various attacks, such as remote code execution, replay attacks, injection attacks, or privilege escalation.
Code Example

Consider a web application that uses serialized objects to represent user sessions. An attacker could tamper with their serialized session cookie to escalate their privileges:

Original Cookie (simplified for demonstration):

{"user": "normalUser", "role": "user"}

Tampered Cookie:

{"user": "attacker", "role": "admin"}

By modifying their session cookie, the attacker might grant themselves administrative privileges.
Mitigation with AWS WAF

AWS WAF can be configured to detect and block common patterns or payloads associated with insecure deserialization attacks.

Sample WAF Rule:

{
    "Name": "BlockInsecureDeserializationPatterns",
    "Priority": 10,
    "Statement": {
        "RegexPatternSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:region:account-id:regional/resourcetype/resource-id",
            "FieldToMatch": {
                "Type": "COOKIE"
            },
            "TextTransformations": [
                {
                    "Type": "URL_DECODE",
                    "Priority": 0
                },
                {
                    "Type": "BASE64_DECODE",
                    "Priority": 1
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockInsecureDeserializationPatterns"
    }
}

This rule references a regex pattern set (specified by the ARN) that contains patterns commonly associated with insecure deserialization attacks. Any cookie matching these patterns will result in the request being blocked.
10. Clickjacking

Clickjacking is a malicious technique where an attacker tricks a user into clicking something different from what the user perceives. This is often achieved by using transparent or opaque layers to deceive the user into performing unintended actions, potentially leading to confidential information disclosure or unintended actions on websites.
Code Example

An attacker might embed a legitimate site within an iframe and overlay a deceptive UI:

<iframe src="http://legitimatewebsite.com" style="opacity:0.5;"></iframe>
<button style="position: absolute; top: 50px; left: 50px;">Click me for a prize!</button>

Users might believe they are clicking the "prize" button, but they interact with the legitimate website within the iframe.
Mitigation with AWS WAF

While Clickjacking is primarily mitigated by setting the X-Frame-Options HTTP header on the server (which tells the browser not to display the site within frames), AWS WAF can be used to monitor and log such attempts, helping to identify potential attackers or malicious sites.

Note: AWS WAF doesn't directly block clickjacking attempts since the defense lies in response headers set by the web server. However, ensuring that your web server sets the appropriate headers is crucial.
11. Bots and Scrapers

Bots and scrapers are automated scripts or software that interact with websites. While some bots, like search engine crawlers, are legitimate, others can overload systems, scrape content, submit spam, or perform other malicious actions.
Code Example

Bots and scrapers often exhibit recognizable behavior patterns:

    High request rates from a single IP address.
    User agents that identify as known scrapers.
    Access patterns that don't resemble human navigation.

Mitigation with AWS WAF

AWS WAF can be configured to detect and block traffic patterns that resemble malicious bots and scrapers.

Sample WAF Rule:

{
    "Name": "BlockSuspiciousBots",
    "Priority": 11,
    "Statement": {
        "OrStatement": {
            "Statements": [
                {
                    "ByteMatchStatement": {
                        "FieldToMatch": {
                            "Type": "USER_AGENT"
                        },
                        "SearchString": "suspiciousBotUserAgent",
                        "TextTransformations": [
                            {
                                "Type": "LOWERCASE",
                                "Priority": 0
                            }
                        ]
                    }
                },
                {
                    "RateBasedStatement": {
                        "Limit": 100,
                        "AggregateKeyType": "IP"
                    }
                }
            ]
        }
    },
    "Action": {
        "Block": {}
    },
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockSuspiciousBots"
    }
}

This rule blocks user-agent requests that match known bot patterns and IP addresses that exceed a specified request rate.
you can use this as a reference for WAF V2 rules:
[ 
      { 
         "Action": { 
            "Allow": { 
               "CustomRequestHandling": { 
                  "InsertHeaders": [ 
                     { 
                        "Name": "string",
                        "Value": "string"
                     }
                  ]
               }
            },
            "Block": { 
               "CustomResponse": { 
                  "CustomResponseBodyKey": "string",
                  "ResponseCode": number,
                  "ResponseHeaders": [ 
                     { 
                        "Name": "string",
                        "Value": "string"
                     }
                  ]
               }
            },
            "Captcha": { 
               "CustomRequestHandling": { 
                  "InsertHeaders": [ 
                     { 
                        "Name": "string",
                        "Value": "string"
                     }
                  ]
               }
            },
            "Challenge": { 
               "CustomRequestHandling": { 
                  "InsertHeaders": [ 
                     { 
                        "Name": "string",
                        "Value": "string"
                     }
                  ]
               }
            },
            "Count": { 
               "CustomRequestHandling": { 
                  "InsertHeaders": [ 
                     { 
                        "Name": "string",
                        "Value": "string"
                     }
                  ]
               }
            }
         },
         "CaptchaConfig": { 
            "ImmunityTimeProperty": { 
               "ImmunityTime": number
            }
         },
         "ChallengeConfig": { 
            "ImmunityTimeProperty": { 
               "ImmunityTime": number
            }
         },
         "Name": "string",
         "OverrideAction": { 
            "Count": { 
               "CustomRequestHandling": { 
                  "InsertHeaders": [ 
                     { 
                        "Name": "string",
                        "Value": "string"
                     }
                  ]
               }
            },
            "None": { 
            }
         },
         "Priority": number,
         "RuleLabels": [ 
            { 
               "Name": "string"
            }
         ],
         "Statement": { 
            "AndStatement": { 
               "Statements": [ 
                  "Statement"
               ]
            },
            "ByteMatchStatement": { 
               "FieldToMatch": { 
                  "AllQueryArguments": { 
                  },
                  "Body": { 
                     "OversizeHandling": "string"
                  },
                  "Cookies": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedCookies": [ "string" ],
                        "IncludedCookies": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "HeaderOrder": { 
                     "OversizeHandling": "string"
                  },
                  "Headers": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedHeaders": [ "string" ],
                        "IncludedHeaders": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "JA3Fingerprint": { 
                     "FallbackBehavior": "string"
                  },
                  "JsonBody": { 
                     "InvalidFallbackBehavior": "string",
                     "MatchPattern": { 
                        "All": { 
                        },
                        "IncludedPaths": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "Method": { 
                  },
                  "QueryString": { 
                  },
                  "SingleHeader": { 
                     "Name": "string"
                  },
                  "SingleQueryArgument": { 
                     "Name": "string"
                  },
                  "UriPath": { 
                  }
               },
               "PositionalConstraint": "string",
               "SearchString": blob,
               "TextTransformations": [ 
                  { 
                     "Priority": number,
                     "Type": "string"
                  }
               ]
            },
            "GeoMatchStatement": { 
               "CountryCodes": [ "string" ],
               "ForwardedIPConfig": { 
                  "FallbackBehavior": "string",
                  "HeaderName": "string"
               }
            },
            "IPSetReferenceStatement": { 
               "ARN": "string",
               "IPSetForwardedIPConfig": { 
                  "FallbackBehavior": "string",
                  "HeaderName": "string",
                  "Position": "string"
               }
            },
            "LabelMatchStatement": { 
               "Key": "string",
               "Scope": "string"
            },
            "ManagedRuleGroupStatement": { 
               "ExcludedRules": [ 
                  { 
                     "Name": "string"
                  }
               ],
               "ManagedRuleGroupConfigs": [ 
                  { 
                     "AWSManagedRulesACFPRuleSet": { 
                        "CreationPath": "string",
                        "EnableRegexInPath": boolean,
                        "RegistrationPagePath": "string",
                        "RequestInspection": { 
                           "AddressFields": [ 
                              { 
                                 "Identifier": "string"
                              }
                           ],
                           "EmailField": { 
                              "Identifier": "string"
                           },
                           "PasswordField": { 
                              "Identifier": "string"
                           },
                           "PayloadType": "string",
                           "PhoneNumberFields": [ 
                              { 
                                 "Identifier": "string"
                              }
                           ],
                           "UsernameField": { 
                              "Identifier": "string"
                           }
                        },
                        "ResponseInspection": { 
                           "BodyContains": { 
                              "FailureStrings": [ "string" ],
                              "SuccessStrings": [ "string" ]
                           },
                           "Header": { 
                              "FailureValues": [ "string" ],
                              "Name": "string",
                              "SuccessValues": [ "string" ]
                           },
                           "Json": { 
                              "FailureValues": [ "string" ],
                              "Identifier": "string",
                              "SuccessValues": [ "string" ]
                           },
                           "StatusCode": { 
                              "FailureCodes": [ number ],
                              "SuccessCodes": [ number ]
                           }
                        }
                     },
                     "AWSManagedRulesATPRuleSet": { 
                        "EnableRegexInPath": boolean,
                        "LoginPath": "string",
                        "RequestInspection": { 
                           "PasswordField": { 
                              "Identifier": "string"
                           },
                           "PayloadType": "string",
                           "UsernameField": { 
                              "Identifier": "string"
                           }
                        },
                        "ResponseInspection": { 
                           "BodyContains": { 
                              "FailureStrings": [ "string" ],
                              "SuccessStrings": [ "string" ]
                           },
                           "Header": { 
                              "FailureValues": [ "string" ],
                              "Name": "string",
                              "SuccessValues": [ "string" ]
                           },
                           "Json": { 
                              "FailureValues": [ "string" ],
                              "Identifier": "string",
                              "SuccessValues": [ "string" ]
                           },
                           "StatusCode": { 
                              "FailureCodes": [ number ],
                              "SuccessCodes": [ number ]
                           }
                        }
                     },
                     "AWSManagedRulesBotControlRuleSet": { 
                        "EnableMachineLearning": boolean,
                        "InspectionLevel": "string"
                     },
                     "LoginPath": "string",
                     "PasswordField": { 
                        "Identifier": "string"
                     },
                     "PayloadType": "string",
                     "UsernameField": { 
                        "Identifier": "string"
                     }
                  }
               ],
               "Name": "string",
               "RuleActionOverrides": [ 
                  { 
                     "ActionToUse": { 
                        "Allow": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Block": { 
                           "CustomResponse": { 
                              "CustomResponseBodyKey": "string",
                              "ResponseCode": number,
                              "ResponseHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Captcha": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Challenge": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Count": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        }
                     },
                     "Name": "string"
                  }
               ],
               "ScopeDownStatement": "Statement",
               "VendorName": "string",
               "Version": "string"
            },
            "NotStatement": { 
               "Statement": "Statement"
            },
            "OrStatement": { 
               "Statements": [ 
                  "Statement"
               ]
            },
            "RateBasedStatement": { 
               "AggregateKeyType": "string",
               "CustomKeys": [ 
                  { 
                     "Cookie": { 
                        "Name": "string",
                        "TextTransformations": [ 
                           { 
                              "Priority": number,
                              "Type": "string"
                           }
                        ]
                     },
                     "ForwardedIP": { 
                     },
                     "Header": { 
                        "Name": "string",
                        "TextTransformations": [ 
                           { 
                              "Priority": number,
                              "Type": "string"
                           }
                        ]
                     },
                     "HTTPMethod": { 
                     },
                     "IP": { 
                     },
                     "LabelNamespace": { 
                        "Namespace": "string"
                     },
                     "QueryArgument": { 
                        "Name": "string",
                        "TextTransformations": [ 
                           { 
                              "Priority": number,
                              "Type": "string"
                           }
                        ]
                     },
                     "QueryString": { 
                        "TextTransformations": [ 
                           { 
                              "Priority": number,
                              "Type": "string"
                           }
                        ]
                     },
                     "UriPath": { 
                        "TextTransformations": [ 
                           { 
                              "Priority": number,
                              "Type": "string"
                           }
                        ]
                     }
                  }
               ],
               "EvaluationWindowSec": number,
               "ForwardedIPConfig": { 
                  "FallbackBehavior": "string",
                  "HeaderName": "string"
               },
               "Limit": number,
               "ScopeDownStatement": "Statement"
            },
            "RegexMatchStatement": { 
               "FieldToMatch": { 
                  "AllQueryArguments": { 
                  },
                  "Body": { 
                     "OversizeHandling": "string"
                  },
                  "Cookies": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedCookies": [ "string" ],
                        "IncludedCookies": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "HeaderOrder": { 
                     "OversizeHandling": "string"
                  },
                  "Headers": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedHeaders": [ "string" ],
                        "IncludedHeaders": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "JA3Fingerprint": { 
                     "FallbackBehavior": "string"
                  },
                  "JsonBody": { 
                     "InvalidFallbackBehavior": "string",
                     "MatchPattern": { 
                        "All": { 
                        },
                        "IncludedPaths": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "Method": { 
                  },
                  "QueryString": { 
                  },
                  "SingleHeader": { 
                     "Name": "string"
                  },
                  "SingleQueryArgument": { 
                     "Name": "string"
                  },
                  "UriPath": { 
                  }
               },
               "RegexString": "string",
               "TextTransformations": [ 
                  { 
                     "Priority": number,
                     "Type": "string"
                  }
               ]
            },
            "RegexPatternSetReferenceStatement": { 
               "ARN": "string",
               "FieldToMatch": { 
                  "AllQueryArguments": { 
                  },
                  "Body": { 
                     "OversizeHandling": "string"
                  },
                  "Cookies": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedCookies": [ "string" ],
                        "IncludedCookies": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "HeaderOrder": { 
                     "OversizeHandling": "string"
                  },
                  "Headers": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedHeaders": [ "string" ],
                        "IncludedHeaders": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "JA3Fingerprint": { 
                     "FallbackBehavior": "string"
                  },
                  "JsonBody": { 
                     "InvalidFallbackBehavior": "string",
                     "MatchPattern": { 
                        "All": { 
                        },
                        "IncludedPaths": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "Method": { 
                  },
                  "QueryString": { 
                  },
                  "SingleHeader": { 
                     "Name": "string"
                  },
                  "SingleQueryArgument": { 
                     "Name": "string"
                  },
                  "UriPath": { 
                  }
               },
               "TextTransformations": [ 
                  { 
                     "Priority": number,
                     "Type": "string"
                  }
               ]
            },
            "RuleGroupReferenceStatement": { 
               "ARN": "string",
               "ExcludedRules": [ 
                  { 
                     "Name": "string"
                  }
               ],
               "RuleActionOverrides": [ 
                  { 
                     "ActionToUse": { 
                        "Allow": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Block": { 
                           "CustomResponse": { 
                              "CustomResponseBodyKey": "string",
                              "ResponseCode": number,
                              "ResponseHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Captcha": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Challenge": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        },
                        "Count": { 
                           "CustomRequestHandling": { 
                              "InsertHeaders": [ 
                                 { 
                                    "Name": "string",
                                    "Value": "string"
                                 }
                              ]
                           }
                        }
                     },
                     "Name": "string"
                  }
               ]
            },
            "SizeConstraintStatement": { 
               "ComparisonOperator": "string",
               "FieldToMatch": { 
                  "AllQueryArguments": { 
                  },
                  "Body": { 
                     "OversizeHandling": "string"
                  },
                  "Cookies": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedCookies": [ "string" ],
                        "IncludedCookies": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "HeaderOrder": { 
                     "OversizeHandling": "string"
                  },
                  "Headers": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedHeaders": [ "string" ],
                        "IncludedHeaders": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "JA3Fingerprint": { 
                     "FallbackBehavior": "string"
                  },
                  "JsonBody": { 
                     "InvalidFallbackBehavior": "string",
                     "MatchPattern": { 
                        "All": { 
                        },
                        "IncludedPaths": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "Method": { 
                  },
                  "QueryString": { 
                  },
                  "SingleHeader": { 
                     "Name": "string"
                  },
                  "SingleQueryArgument": { 
                     "Name": "string"
                  },
                  "UriPath": { 
                  }
               },
               "Size": number,
               "TextTransformations": [ 
                  { 
                     "Priority": number,
                     "Type": "string"
                  }
               ]
            },
            "SqliMatchStatement": { 
               "FieldToMatch": { 
                  "AllQueryArguments": { 
                  },
                  "Body": { 
                     "OversizeHandling": "string"
                  },
                  "Cookies": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedCookies": [ "string" ],
                        "IncludedCookies": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "HeaderOrder": { 
                     "OversizeHandling": "string"
                  },
                  "Headers": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedHeaders": [ "string" ],
                        "IncludedHeaders": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "JA3Fingerprint": { 
                     "FallbackBehavior": "string"
                  },
                  "JsonBody": { 
                     "InvalidFallbackBehavior": "string",
                     "MatchPattern": { 
                        "All": { 
                        },
                        "IncludedPaths": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "Method": { 
                  },
                  "QueryString": { 
                  },
                  "SingleHeader": { 
                     "Name": "string"
                  },
                  "SingleQueryArgument": { 
                     "Name": "string"
                  },
                  "UriPath": { 
                  }
               },
               "SensitivityLevel": "string",
               "TextTransformations": [ 
                  { 
                     "Priority": number,
                     "Type": "string"
                  }
               ]
            },
            "XssMatchStatement": { 
               "FieldToMatch": { 
                  "AllQueryArguments": { 
                  },
                  "Body": { 
                     "OversizeHandling": "string"
                  },
                  "Cookies": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedCookies": [ "string" ],
                        "IncludedCookies": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "HeaderOrder": { 
                     "OversizeHandling": "string"
                  },
                  "Headers": { 
                     "MatchPattern": { 
                        "All": { 
                        },
                        "ExcludedHeaders": [ "string" ],
                        "IncludedHeaders": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "JA3Fingerprint": { 
                     "FallbackBehavior": "string"
                  },
                  "JsonBody": { 
                     "InvalidFallbackBehavior": "string",
                     "MatchPattern": { 
                        "All": { 
                        },
                        "IncludedPaths": [ "string" ]
                     },
                     "MatchScope": "string",
                     "OversizeHandling": "string"
                  },
                  "Method": { 
                  },
                  "QueryString": { 
                  },
                  "SingleHeader": { 
                     "Name": "string"
                  },
                  "SingleQueryArgument": { 
                     "Name": "string"
                  },
                  "UriPath": { 
                  }
               },
               "TextTransformations": [ 
                  { 
                     "Priority": number,
                     "Type": "string"
                  }
               ]
            }
         },
         "VisibilityConfig": { 
            "CloudWatchMetricsEnabled": boolean,
            "MetricName": "string",
            "SampledRequestsEnabled": boolean
         }
      }
   ]
Naming of the rule should be [rule name]-[CVE ID], if it has no CVE ID you can return the disover date insted, please only use only avalable parameters. These parameters should always be present in every rules: Name,Priority,VisibilityConfig ,and Action, Now thoughtfully analyze and created a WAF rules for this exploitation: 
""")