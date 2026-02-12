# What?

Gonna try to refine this into something meaningful, but the gist is, wanted a tool that could pull sample details from HA and turn them into yara rules. Told copilot to run it, did some basic debugging to get it up and running.

The rules might suck right now, but wanting to get them more useful over time. 

The current goals:
- validate and fix yara rule generations
- validate and fix sigma rule generations
- the suricata rules work better than the others, but it's just cause it found things and said omg ip addresses. For the love of all things don't use these.

# Why?

Hybrid analysis didn't have a way to pull yara rules, and I didn't want to just parse straight to yargen or something. Maybe I should have just done that. Copilot didn't seem to think it the thing to do either, so whatever. 

# How?

- set your hybrid analysis api key with the environment variable HA_API_KEY
- then run the python script

```
export HA_API_KEY=ajeioejne....
./copilot-hatoyara.py
```
