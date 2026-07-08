# Free-use policy

Argus itself is MIT-licensed software. You can use, modify, and run this local desktop app without paying Argus.

## Collector cost model

Argus collectors are designed to be free to run:

- Keyless public-source collectors use public pages, public feeds, public APIs, or generated review links without requiring payment.
- Optional credentialed collectors use user-provided keys from services that offer free developer access or free public API tiers. These keys are stored in the operating-system credential vault.
- Argus does not require paid SaaS subscriptions, hosted Argus accounts, paid proxy networks, CAPTCHA bypass services, or commercial enrichment APIs.

## Social media boundary

Social platform coverage is split into two lawful categories:

- Live collectors where a platform exposes free public data without a paid API key, such as Reddit public profile JSON, Bluesky public AppView, Mastodon public instance APIs, Hacker News Firebase, GitHub/GitLab public APIs, Keybase public profiles, Gravatar public profiles, and YouTube public channel RSS/page metadata.
- Unverified lead collectors for platforms that restrict free API access or require login for reliable live data, such as X, Instagram, Facebook, Threads, TikTok, LinkedIn, Pinterest, Snapchat, Telegram, Twitch, Medium, Substack, Tumblr, Flickr, SoundCloud, Vimeo, Patreon, Linktree, and similar public profile URL patterns.

Argus does not bypass login requirements, scrape private content, defeat rate limits, or claim that matching handles prove identity. Platform URLs are review leads unless a collector directly verifies a public profile through a public endpoint.

## Data-broker and Whitepages-style sources

People-search and data-broker collectors generate public review links for sources such as Whitepages, Spokeo, TruePeopleSearch, FastPeopleSearch, BeenVerified, Nuwber, ThatsThem, PeopleFinders, and related public-record sites. When Argus knows a public manual opt-out or privacy route, it includes that URL beside the search lead.

These leads are not automated removals. Argus does not submit forms, solve CAPTCHAs, create accounts, pay for reports, or claim that a matching listing belongs to the subject. The investigator reviews each source and performs any removal request manually.

## Email unsubscribe safety

The email unsubscribe collector parses pasted raw headers/source or local `.eml` files for standards-based fields such as `List-Unsubscribe` and `List-Unsubscribe-Post`. It reports mailto and URL options, one-click support, list metadata, and sender domains without opening links or sending mail.

Argus does not connect to your mailbox, click unsubscribe URLs, or send unsubscribe emails. For suspicious messages, use provider-native unsubscribe controls or block/report tools instead of visiting links in the message.

## Election registration and household boundaries

Election registration collectors link to official resources such as Vote.gov, NASS Can I Vote, USA.gov guidance, and state resources reached through those official directories. Argus does not retrieve voter rolls, determine whether a named person is registered, infer party affiliation, or automate voter-record lookups.

Household collectors use the free official U.S. Census Geocoder for address/geography context and produce address-level public-record search leads for property, recorder, GIS, and election-office sources. They do not identify residents, scrape household rosters, or assert who lives at an address.

## Operator responsibility

Third-party services can change their free tiers, rate limits, API policies, and terms of service. Argus avoids paid dependencies, but operators remain responsible for checking whether their use of each public source is lawful and permitted for their investigation, jurisdiction, and volume.
