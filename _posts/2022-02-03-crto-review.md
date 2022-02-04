---
title: CRTO Review (Certified Red Team Operator) & Notion Templates
date: 2022-02-03 16:08:49 +0100
categories: [Miscellaneous, Certifications]
tags: [CRTO, Cobalt Strike, Red team]
image: /assets/img/crto/CRTO.png
pin: true
---

A few days ago, I earn the [CRTO badge](https://eu.badgr.com/public/assertions/rAayO2s_QsiiRvwDzMtXsg) from [Zero-Point Security](https://www.zeropointsecurity.co.uk/).

While I [was passing the OSCP](/posts/oscp-review/), I watched almost all videos from Andy Li's YouTube channel to accompany me during the journey, and this one in particular caught my attention ⬇️

<p align="center">
<iframe width="560" height="315" src="https://www.youtube.com/embed/UDSjsp8cYC0" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</p>

It was the first time that I heard about a Red Team certification, so I decided that it would be my next goal once I will be done with OSCP.

**CRTO** stands for Certified Red Team Operator.

The exam involves compromising at least 6 out of 8 machines, in 48 hours which you can split in a four days window.

**TL;DR** ➡️ I definitely recommend the course. I failed at my first attempt and succeeded at my second one (three days after). In this blog post, I’ll tell my story and share some advice. Here are some things you will get if you decide to take this training:

➡️ a LIFE TIME ACCESS to all the updates of the course

➡️ an instance of `Splunk` to look at the indicators you may leave

➡️ and the opportunity to use `Cobalt Strike` C2 without breaking the bank 

> I am neither a native speaker nor a security expert. Please do not hesitate to correct me if you think I’m wrong. There is a `Disqus` comment section below.

- [🏴‍☠️ Red team engagement vs Penetration test (Thoughts on real-world threat actors)](#%EF%B8%8F-red-team-engagement-vs-penetration-test-thoughts-on-real-world-threat-actors)
- [📖 Zero-Point Security - Red Team Ops course](#-zero-point-security---red-team-ops-course)
- [🧑‍🏫 Recommendations for CRTO aspirants](#-recommendations-for-crto-aspirants)
- [🧑‍🎓 My journey](#-my-journey)
  - [🎒 Background](#-background)
  - [⚗️ Lab](#️-lab)
  - [⏱️ Exam](#%EF%B8%8F-exam)
    - [❌ First attempt](#-first-attempt)
    - [✅ Second attempt](#-second-attempt)
  - [🏅 Receiving the badge](#-receiving-the-badge)
  - [💶 Cost (€ / £)](#-cost---)
  - [🤔 Final thoughts](#-final-thoughts)
- [📚 Notion Templates for note taking](#-notion-templates-for-note-taking)
- [🛣️ What I want to study next?](#%EF%B8%8F-what-i-want-to-study-next)
- [🌐 Useful resources](#-useful-resources)
  - [🧐 Reviews](#-reviews)
  - [Malleable C2 profile](#malleable-c2-profile)
  - [Red teamer Guides](#red-teamer-guides)
  - [Miscellaneous](#miscellaneous)

---

# 🏴‍☠️ Red team engagement vs Penetration test (Thoughts on real-world threat actors)

According to Joe Vest and James Tubberville in their (excellent) book “[**Red Team Development and Operations: A practical guide**](https://redteam.guide/)”:

> <span style="color:#FF0000">Red Teaming</span> is the process of using [tactics](https://attack.mitre.org/tactics/enterprise/), [techniques](https://attack.mitre.org/techniques/enterprise/) and procedures (TTPs) to emulate a [real-world threat](https://attack.mitre.org/groups/), with the goal of measuring the effectiveness of the people, processes and technologies used to defend an environment.

- **Tactics** are the technical goals a threat may use during operation.
    
    <u>Examples</u>: Reconnaissance, Bypassing Defenses, Privilege Escalation, Persistence, Exfiltration and so on.
    
- **Techniques** describe the actions threats take to achieve their objectives.
    
    <u>Examples</u>: Password Spraying, ARP Cache Poisoning, Exploiting SUID/SGID binaries, SID-History Injection, etc.
    
- **Procedures** are the technical steps required to perform an action.
    
    <u>Example</u>: for reconnaissance, attackers might collect information about the target, identify key individuals and enumerate externally exposed services.
    

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
<p>🥷&nbsp;Broadly speaking, a pentest (penetration test) consists in discovering and <u>exploiting as much vulnerabilities as possible in a single system</u>, network or application in a short period of time (1 or 2 weeks).</p>

<p>The goals are to identify the vulnerabilities before adversaries do, measure the impact/risks associated with the exploitation of these security flaws, and obviously reduce the attack surface.</p>

<p><u>Pentesters can use “noisy” tools and don’t care about detection since people are aware of their presence.</u></p>
</aside>

<p style="font-size: 0.06rem;"></p>

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
<p><img src="/assets/img/crto/RED_NINJA.webp" alt="/assets/img/crto/RED_NINJA.webp" width="25px" style="left: 1.5%;"/> Whilst in a <span style="color:#FF0000">Red Team</span> engagement, operators emulate a real-world threat and have a clear objective defined by the organization.</p>

<p>The key role of a <span style="color:#FF0000">Red Team</span> is to challenge the <span style="color:#3B88C3">Blue Team</span>: assess tools (AV, IDS, EDR, SIEM...), people and processes (incident response, awareness...). Operators usually work with Threat Intelligence specialists to define a threat profile, a scenario and specific TTPs.</p>

<p>Defenders (<span style="color:#3B88C3">Blue Team</span>) may or may not be informed about an engagement, so <u><b>Red team members care about detection and stealth</b></u>.</p>

The aim is to measure security operations capabilities as a whole, while a pentest focus on a technical control of a specific area.
A red team engagement should last longer than a penetration test. 

<p>Moreover, Red Team operators may find a weakness (vulnerability, unpatched system, misconfiguration) but choose to not take advantage of it to achieve their goal</p>
</aside>
<p style="font-size: 0.06rem;"></p>
The differences in terms of scope and provided details between a Pentest and a Red Team engagement can be shown in this chart of [outpost24](https://outpost24.com/blog/what-type-of-pen-test-do-you-need):

![](/assets/img/crto/pentest-chart.png)

It is well explained in this video of **thehackerish** ⬇️  

<p align="center">
<iframe width="560" height="315" src="https://www.youtube.com/embed/dj0ZGncyAUA" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</p>

The only thing I would add is the following:

Contrary to what I thought, real world threat-actors do not necessarily follow the steps:

1️⃣ scanning for vulnerabilities → 2️⃣ exploit → 3️⃣ profit. 

In reality, they take several steps to get an initial compromise, establish persistence/command and control, evaluate weaknesses, move laterally and perform situational awareness in order to achieve their goals. 

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
⚠️ &nbsp;As a matter of fact, this is a thing you will notice in the course. Indeed, you’ll realize that you don’t need to rely on aggressive port scans to perform enumeration, move laterally in a network and gain high privileges on your target.
</aside>

---

# 📖 Zero-Point Security - Red Team Ops course

When I went through the course material, I really felt that the instructor ([@RastaMouse](https://twitter.com/_rastamouse)) made a huge effort to summarize each concepts.

It is well written, clear, concise, the information are easy to digest. 

Generally, 1 page = 1 new notion (for example COM Hijacking or "The Printer Bug"). 

It is presented in such a way that you’ll have a short description of the concept, tools and techniques along with useful command lines and OPSEC consideration notes.

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
ℹ️&nbsp;Operations Security (OPSEC) is a term to <b>describe the "ease" with which actions can be observed by your "enemy"</b>.

In this particular case, opposing sides are attackers (<span style="color:#FF0000">Red Team</span>) and defenders (<span style="color:#3B88C3">Blue Team</span>)
</aside>

I don’t want to re-write the whole course syllabus but you’ll learn a lot about **Domain enumeration**, **Phishing**, **Delegation types**, **Bypassing defenses** (AV, AppLocker, PowerShell Constrained Language Mode), **Lateral Movement/Pivoting**, **MS SQL abuses**, **LAPS**, **User impersonation** and much more.

The day I finished my exam, I received a mail telling me that the RTO course was moved from [Canvas](https://www.canvas.net/) to the [Thinkific](https://www.thinkific.com/) platform. 

I took a look at it and it seems much “prettier” and pleasant to move from one module to another quickly.

The nice thing about Canvas was the “Search Tool” 🔍 to look for keywords or specific tools/command lines. 

I didn’t find a similar search function on Thinkific but maybe I didn’t investigate enough 🤷.

![Thinkific page](/assets/img/crto/Thinkific.png)

The lab is accessible via [SnapLabs](https://www.snaplabs.io/) so you can do everything in your browser. 

A Kali and a Windows VM are available (for both the exam and the training lab) to attack an Active Directory composed of three forests.

![forest.png](/assets/img/crto/forest.png)

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
⚠️ This implies that there are no VPN connection like for the OSCP and you cannot bring your own tools (except if you do some “magic”) but trust me, everything you need is already here.
</aside>

---

# 🧑‍🏫 Recommendations for CRTO aspirants

1️⃣ Follow the modules in the order they are presented to you. The lab is created in a way that some steps depends on others.  

2️⃣ As you go through the course, don't wait for to see an "exercise" section to reproduce what you just learned.

3️⃣ Take effective notes and as always **build you own cheat sheet**.

4️⃣ Once you booked your exam, the **Threat Profile** that you need to emulate, is directly available in SnapLabs! Download it and build your custom C2 profile for Cobalt Strike, test it on the training lab and ensure it works. This will save you a lot of time!  

5️⃣ Sometimes you can feel lazy about reproducing some parts of the course in your lab. My suggestion is: as long as you’re able to understand it and reproduce it quickly, if this is not a step required to move forward, take some notes and skip it.

6️⃣ Even if you’re already familiar with some tools, do not hesitate to experiment with the different options they offer (`Mimikatz`, `Rubeus`, etc.) There can be different ways for doing the same thing.

7️⃣ Look at the Splunk logs and try to understand the evidences you are letting behind you. It’s an invaluable experience that you have Splunk and Cobalt Strike already set up for you to experiment. 

8️⃣ It’s better to have some knowledge about Windows Active Directory and Kerberos before jumping in. 

I recommend doing the Section 4 of the [Offensive Learning](https://tryhackme.com/path/outline/pentesting)/[Comptia Pentest+](https://tryhackme.com/path/outline/pentestplus) path on [TryHackMe](https://tryhackme.com/).

9️⃣ Read some reviews, they are gold mines!

🔟 Think “Persistence” in the training lab, even if this is not mentioned.

---

# 🧑‍🎓 My journey

## 🎒 Background

I have no prior professional experience in Active Directory Penetration test.

I only learned a few stuff about Kerberos *roasting, Silver/Golden Tickets, and how AD basically works while doing my OSCP prep. 

I just graduated and didn’t start a job in infosec yet.

## ⚗️ Lab

I spent 18 hours in total in the lab, watched every single video, took as many notes as I could. 
Basically, I rewrote the whole course in my own words.
I also built a new cheat sheet with all the concepts, steps and command lines.
Unfortunately, this time, I will not share it with you cause this would involve me leaking course content.

## ⏱️ Exam

### ❌ First attempt

As I mentioned before, I failed my first attempt. Here is what happened:

- It had already been over a month since I had started the course, I had just finished reading each module and had taken a lot of notes.
- I felt that I was not ready for the exam but rather than taking more time to redo some exercises, I preferred to try the exam directly.
    - I was convinced that even if I fail, I would know what to expect for a future attempt.
- The night before the exam and throughout the week, I was sick (maybe Covid?)
- I spent 2-3 days to get my custom C2 profile working BECAUSE OF ONE LINE 🤯!!! 
    - [`c2lint`](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_checking-errors.htm#_Toc65482836) didn’t warned me about the error, but it was a very dumb one.
    - I should have tried writing and testing my custom C2 profile before taking the exam.
- Once the C2 profile was no longer a problem, everything went smoothly and I collected 4 flags in a short amount of time.
- Then I was stuck (maybe because I was too much concerned about OPSEC)
- I couldn’t use all the hours dedicated for the exam because I had to travel ⬅️ assuredly because of a bad time management

### ✅ Second attempt

A few days after my failing experience, I took some time to reread all my notes, go through each course module to check if I missed some interesting command lines.

The second attempt was more “enjoyable” because I knew how to get to the 4th flag quickly.

Nevertheless, I still took the time to do proper enumeration and carry out several post-exploitation activities.

I think the way I managed to get the fifth and sixth flag was not the intended path. 

The reason why I am saying this is because it wasn’t as elegant as the previous techniques and above all, it had a pretty bad OPSEC. I’m almost sure that it was not the way it was supposed to be done. However, I still managed to compromise the different machines and achieve the objective of the exam. 

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
💡 <b>TODO</b>: I have to ask RastaMouse about the intended way...
</aside>

## 🏅 Receiving the badge

My 4 days window for the exam ended at 10:30 AM on February the 1st. I knew that I passed because on January the 30th, I collected the 6 flags required to pass the exam.

At 12:59 PM the same day, I received an email from badgr.

![](/assets/img/crto/badgr.png)

## 💶 Cost (€ / £)

- **Course**: 409,32 € = 349 £GB
- **40 hours of lab access**: 58,64 € = 50 £GB
    - I spent 18 hours in total and I plan to continue to use the hours I have left to experiment new things.
- **Second exam attempt**: 119 € = 99 £GB

## 🤔 Final thoughts

- I know for sure that the course material is a resource that I will often return to.
- Attackers should be creative, try to bypass defense mechanisms and find their way in. There are multiple methods to achieve an objective.
    - Besides the fact that I have acquired a lot of technical knowledge throughout this training, I feel that the main lesson of the course is: “**there is always a way**”.
    - I failed the first time because I wasn’t thinking outside the box, I wasn’t enough creative!
- Most of the things we exploited in the lab were not vulnerabilities (such as *Eternal Blue* or *SambaCry*) but misconfigurations, Kerberos implementation with Microsoft specifics, and features of Active Directory.
    - For example: the <span style="color:#FFEA00">Golden Ticket</span> technique is not a vulnerability in itself.
- Cobalt Strike was so cool to use. I wish I can bring it with me for each challenge/engagements I will face in the future.
    
    I understand why it is a such popular tool. Nevertheless, it remains an expensive tool and I need to familiarize myself with other C2 such as [Covenant](https://github.com/cobbr/Covenant), [PoshC2](https://github.com/nettitude/PoshC2) and much more from the [C2 matrix](https://www.thec2matrix.com/)!

- <span style="color:#FF0000">Red</span> cannot exist without <span style="color:#3B88C3">Blue</span>. The goal of an operator is to bring value to the organization.

<aside style="color:white; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
❓ <b>Are real-world threat actors using zero days or esoteric exploits in their malware/ransomware campaign?</b>

If we take a look at the <a href="https://github.com/silence-is-best/files/blob/main/translate_f.pdf">CONTI Ransomware Gang’s Leaked Hacker’s Manual</a> ⇒ it seems like a procedure that a “non-technical” person could follow more than a documentation to exploit crazy heap-overflow and bypassing ASLR.
</aside>

---

# 📚 Notion Templates for note taking

- <https://amplified-maize-ada.notion.site/Red-Team-Ops-C-R-T-O-Certified-Red-Team-Operator-126b651095fa4821a91ceb0bf1c48392>

---

# 🛣️ What I want to study next?

- [Sektor7](https://institute.sektor7.net/) Malware Development Courses
- [C2 Development Course](https://courses.zeropointsecurity.co.uk/courses/c2-development-in-csharp) by Zero-Point Security
- [OSEP](https://www.offensive-security.com/pen300-osep/)
- [HackTheBox Pro labs](https://www.hackthebox.com/hacker/pro-labs)
- [TCM courses](https://academy.tcm-sec.com/) (Practical Phishing engagement, Movement, Pivoting and Persistence, etc.)
- Improving my Reverse Engineering skills via [Zero2Auto](https://courses.zero2auto.com/) course
- Taking a look at [Blue Team Labs](https://blueteamlabs.online/) and [Cyber Defenders](https://cyberdefenders.org/)
- [OSWE](https://www.offensive-security.com/awae-oswe/), [OSED](https://www.offensive-security.com/exp301-osed/) and [OSWP](https://www.offensive-security.com/wifu-oswp/)

---

# 🌐 Useful resources

## 🧐 Reviews

- [**thehackerish** - Certified Red Team Operator (CRTO): 🧐 HONEST Review 🧐](https://www.youtube.com/watch?v=dtRmZ1cpSRU)

- [HuskyHacks - Zero-Point Security Red Team Ops 2021 Update](https://huskyhacks.dev/blog-feed/page/2/)

- [**0xash** - Zero-Point Security's Certified Red Team Operator (CRTO) Review](https://0xash.io/Certified-Red-Team-Operator-Review/)

- [Red Team Ops Course Review](https://blog.sunggwanchoi.com/red-team-ops-course-review/)

- [CRTO review - Red-Team Ops from Zero Point Security](https://www.alluresec.com/2021/12/25/red-team-ops-review/)

- [**Andy Li** - Certified Red Team Operator (CRTO) - Exam Experience](https://www.youtube.com/watch?v=P2ioSJdcAJw)

- [**Andy Li** - Certified Red Team Operator (CRTO) Course Review](https://www.youtube.com/watch?v=2IPxJSIe-lk)

- [Operate Like You Mean It: 'Red Team Ops' (CRTO) Course Review](https://casvancooten.com/posts/2021/07/operate-like-you-mean-it-red-team-ops-crto-course-review/)

- [ryan412/ADLabsReview: Active Directory Labs/exams Review](https://github.com/ryan412/ADLabsReview#red-team-ops--certified-red-team-operator)

## Malleable C2 profile

- [Exercising Caution with Malleable C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_dangerous.htm#_Toc65482851)

- [Understanding Cobalt Strike Profiles - Updated for Cobalt Strike 4.5](https://blog.zsec.uk/cobalt-strike-profiles/)

- [A Deep Dive into Cobalt Strike Malleable C2](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)

- [[RED TEAM] Cobalt Strike 4.0+ Malleable C2 Profile Guideline](https://infosecwriteups.com/red-team-cobalt-strike-4-0-malleable-c2-profile-guideline-eb3eeb219a7c)

## Red teamer Guides

- [ired.team](https://www.ired.team/)

- [redteamer.tips](https://redteamer.tips/)

- [The C2 Matrix](https://www.thec2matrix.com/matrix)

## Miscellaneous

- [MSSQL Cheat Sheet](https://cheats.philkeeble.com/active-directory/mssql)

- [Cobalt Strike 3.3 - Now with less PowerShell.exe - Cobalt Strike Research and Development](https://www.cobaltstrike.com/blog/cobalt-strike-3-3-now-with-less-powershell-exe/)

- [**Zero-Point Security** - Red Team Ops Exam](https://www.zeropointsecurity.co.uk/red-team-ops/book-exam)

- [**Adsecurity** - Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)

- [**harmj0y** - The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)

- [Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)

- [PowerTip: Use PowerShell to Get a List of Computers and IP Addresses from Active Directory](https://devblogs.microsoft.com/scripting/powertip-use-powershell-to-get-a-list-of-computers-and-ip-addresses-from-active-directory/)

- [App-o-Lockalypse now!](https://fr.slideshare.net/OddvarHlandMoe/appolockalypse-now)

- [Red Team 2021 - NoLimitSecu](https://www.nolimitsecu.fr/red-team-2021/)

- [Red Team - Blue Team - NoLimitSecu](https://www.nolimitsecu.fr/red-team-blue-team/)

- [Tactics, Techniques, and Procedures (TTPs)](https://azeria-labs.com/tactics-techniques-and-procedures-ttps/)