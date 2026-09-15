---
layout: null
permalink: /
---
SAFE_POST_URL_REGEX_REACHABILITY

The tag below names the nonexistent literal directory `(?:foo)?`, but it can
resolve the post in the real `foo` directory only if the directory component is
interpreted as regular-expression syntax:

CANARY_LINK={% post_url (?:foo)?/2020-01-01-canary %}

