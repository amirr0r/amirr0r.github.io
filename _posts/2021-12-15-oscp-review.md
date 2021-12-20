---
title: OSCP Review (Cheat Sheet, Tmux Enumeration Scripts and Notion Templates) 
date: 2021-12-15 03:44:02 +0100
categories: [Miscellaneous, Certifications]
tags: [oscp-prep, oscp]
image: /assets/img/oscp/offsec.png
pin: true
---

About a month ago (10 November 2021), I got [my OSCP certification](https://www.credly.com/badges/c8986c46-85b3-4c32-b99a-f9039cb961a9).

OSCP stands for Offensive Security Certified Professional. It consists in a 24-hour proctored exam to compromise 5 machines. 

The only initial information is their IP addresses.

Once these 24 hours have passed, we have 24 hours left to write a report describing the steps that allowed us to gain access to each target as a high privileged user (administrator). The report should contain the discovered vulnerabilities, their severities, a brief description on how to fix them as well as exploitation code.

To prepare for the exam, Offensive Security gives you access to a lab (with more than 70 machines) with different options depending on how long you want to access to it. 

A week before taking the exam, I felt that I wasn't ready. Finally, I got the OSCP at my first attempt 🎉. 

# Table of contents

1. [🤔 General thoughts about the certification](#-general-thoughts-about-the-certification)
2. [🧑‍🏫 Recommendations for OSCP aspirants](#-recommendations-for-oscp-aspirants)
3. [🧑‍🎓 My personal journey](#-my-personal-journey)
  - [🎒 Background](#-background)
  - [🥼 Preparation and PWK Lab](#-preparation-and-pwk-lab)
  - [⌛ Exam Timeline](#-exam-timeline)
  - [📝 Writing the report](#-writing-the-report)
  - [✉️ Getting the certification](#️-getting-the-certification)
4. [🛣️ What's next?](#️-whats-next)
5. [🎁 Scripts, cheat sheet and templates I would like to share](#-scripts-cheat-sheet-and-templates-i-would-like-to-share)
  - [📚 Notion templates](#-notion-templates)
  - [📋 Cheat Sheet + Scripts](#-cheat-sheet--scripts)
6. [Some interesting links](#some-interesting-links)

# 🤔 General thoughts about the certification

1. Although many people interested in infosec want to get the OSCP, it remains an **entry level certification**. More advanced certifications could be OSEP or OSWE.

2. The course is huge (850-page PDF course guide, 17+ hours of video) and <u>covers a wide variety of penetration testing fundamentals</u> (enumeration, looking for unpatched services and/or applications, modifying exploits, privilege escalation...).

3. Going through **the lab will allow you to approach more advanced concepts than those necessary for the exam**.
    
    Indeed, the lab contains over 70 machines in different networks. This implies that you have to perform port redirection, tunneling, pivoting, lateral movement and so son. Many machines are part of a chain (they have dependencies on each others) so **post-exploitation** **is as important as gaining an initial foothold**. 
    
    It's all about <u>developing an intuition and a methodology</u> for the exam and your future security assessments.
    
    ![PWK Lab](/assets/img/oscp/review/PWK_LAB.png)
    
4. **The exam is not that hard**, since you know there are vulnerabilities and probably public exploits. [ExploitDB](https://www.exploit-db.com/) and Google are your friends. Think also about common misconfigurations or capabilities that can lead to code execution!  

5. I had OSCP in mind for a few years now, but I was discouraged by people telling me that security certifications were useless. 
    
    Ultimately, I do believe that technical certifications are not necessary in our field but they can be beneficial in that they allow people to set a goal and ensure that some time has been spent studying very specific concepts. 
    
    **Disclaimer**: Here, I am not talking about certifications based on multiple choices questionnaires.
    
    Keeping in mind that certs remain recognized in our profession and that they are HR filters.
    
    Overall, I really enjoyed my OSCP experience and definitely learned a lot throughout the journey.
    
    <blockquote class="twitter-tweet"><p lang="en" dir="ltr">When you laugh at infosec certifications, you indiscriminately also laugh at passionate people that have been hustling for years.<br><br>Is a cert required? No. Does it often help people to set goals and work towards them? Hell yes. <a href="https://t.co/glyVrZoJJA">pic.twitter.com/glyVrZoJJA</a></p>&mdash; Wim &quot;The New Normal&quot; Remes (@wimremes) <a href="https://twitter.com/wimremes/status/1443862277678059520?ref_src=twsrc%5Etfw">October 1, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> 
    

# 🧑‍🏫 Recommendations for OSCP aspirants

1. **Build your own Cheat Sheet** while doing your preparation, the PWK lab and course exercises, so you can easily copy and paste useful commands. *My personal cheat sheet is available [here](https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md#boot2root-cheatsheet) 😉*

2. Don't be ashamed to use the student forum if you went through every tactics in your cheat sheet/methodology. **You don't know what you don't know!**

3. Offsec has recently added [5 retired OSCP exam machines in the IT network of the PWK lab](https://www.offensive-security.com/offsec/introduction-of-recently-retired-oscp-exam-machines-in-pwk-labs/). Make sure to do them before the exam.

4. Read reviews on [`r/oscp`](https://www.reddit.com/r/oscp/) and various blog posts. You can really benefit from the experience of others (success and failure stories, tools and methodology...).

5. Do not do all the course exercises except you have A LOT of time! Focus only on parts that you're not familiar with (Antivirus Evasion for instance). Even if I was familiar with most of the concepts and tools mentioned in the course, it took me almost a month to finish them.  

6. Take effective notes using whatever tool suits you ([Notion](https://www.notion.so/), [Cherry Tree](https://www.giuspen.com/cherrytree/), [Obsidian](https://obsidian.md/), Markdown files in [VScode](https://code.visualstudio.com/) and so on).

7. Write scripts that can automate your enumeration and prepare a skeleton script for the Buffer Overflow machine _(this second advice is no longer valid considering the [2022 exam update](https://www.offensive-security.com/offsec/oscp-exam-structure/))_.
    - My Tiny Enumeration `Tmux` Organizer Scripts (TETOS): <https://github.com/amirr0r/TETOS>

      ![TETOS demo](https://github.com/amirr0r/TETOS/blob/main/TETOS_demo.gif?raw=true)

    - My buffer overflow skeleton exploit: <https://github.com/amirr0r/notes/blob/master/Infosec/Pwn/shellcode-stack-buffer-overflow-exploit-skeleton.py>

# 🧑‍🎓 My personal journey

## 🎒 Background

I'm 23. At 18, I started to learn about computer science (programing, database management, networks, etc.). I spent a year as a developer in apprenticeship and 3 years as an apprentice cybersecurity engineer focused on embedded systems.

> _Apprenticeship consists in switching between studying in school and working at a company for a short period of time during one or many years. It could be 2 days a week or 1 month at the company and 1 month at school. During school holidays you have to work at the company, you are a real employee._

![background-dj.gif](/assets/img/oscp/review/background-dj.gif)

Now that I have the certification I think that I was quite able to pass it several years ago if I did not procrastinate so much (but maybe it's just a bias). However, I am glad that I have passed it this year as I was able to benefit from the [course update of 2020](https://www.offensive-security.com/offsec/pwk-2020-update/).

## 🥼 Preparation and PWK Lab

1. Before jumping to the OSCP, I went through [a preparation plan](https://amirr0r.github.io/posts/oscp-prep/) to learn about basic enumeration and exploitation as well as file transfer, upgrading shells, Linux and Windows privilege escalation famous methods. As you can see in my blog post *"[How do I prepare for the OSCP?](https://amirr0r.github.io/posts/oscp-prep/)"*, I didn't complete all the things I planed 🤷. It took me several months since I was working and studying at the same time and I wrote write-ups for (almost) all the machines I did from [HacktheBox](https://www.hackthebox.com/), [Vulnhub](https://www.vulnhub.com/) and [Tryhackme](https://tryhackme.com/). 

2. I "really" started on September 10th. In September I compromised about 30-35 machines, did all the Big Four and unlocked the IT Department Network. During October, I completed all the course exercises, watched all the videos and I have read the entire PDF even though I was familiar with the most of it because of the [preparation](https://amirr0r.github.io/posts/oscp-prep/). The reason was: I didn't want to miss any small tricks I could benefit from.

3. From the end of October to the beginning of November, I compromised more than 20 machines (including the [5 retired OSCP exam machines](https://www.offensive-security.com/offsec/introduction-of-recently-retired-oscp-exam-machines-in-pwk-labs/)) then I passed the exam.

4. After taking the exam, I continued to attack some machines resulting in 58 compromised machines at the end of my lab access. Unfortunately I didn't compromised all of the 70.   

## ⌛ Exam Timeline

<aside style="color:white; display: flex; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
ℹ️ While I was doing the exam, I was taking notes for the report and I took several breaks. I recommend you to do the same if you're planning to pass the exam.
</aside>

➡️ **14h - 14h56**: My exam started approximately at 2 PM (got some issues with proctor software). I finished the Buffer overflow machine within an hour while running enumeration scripts in the background for each target.

➡️ **15h - 15h48**: I took a small break then I decided to attack the 10 pointer machine. "Luckily", I identified the exploitation path very quickly. After completing it, I took another break.

➡️ ~**16h10 - 18h45**: I looked at the output of my enumeration script to find some low hanging fruits. Decided to go through two machines simultaneously. After almost 2 hours, I got a low privileged shell on a 20 pointer machine then I went to another break.  

➡️ ~**19h - 20h17**: Finding the privilege escalation method was pretty straightforward, while the exploit was running I jumped to the other machine. Finally, I went back and saw that I became the super user 😎

➡️ ~**20h30 - 22h53**: I fell into many rabbit holes until I found a way to execute code on the remote machine. Yes! Now I just need to find a way to privesc in order to obtain more than 70 points required to get the OSCP. I took a longer break of approximately 1h30-2h to walk outside and come back with a resting mind.

➡️ ~**00h30** - **03h06**: Since my shell wasn't stable I used my `Meterpreter` bullet to upgrade my shell. I also wanted to ensure that I will be able to reproduce each steps for the report so I reverted the machine and I did it once again. Privilege escalation was very obvious but I took many hours to try different ways listed in the privesc enumeration script. If I write the report correctly, I must have 75 points and get the certification 💪! 

After that, I left the screen immediately. I went to sleep approximately at 6h30 then I woke up at approximately at 12h. Until the end of the 24 hours exam, I tried to attack the last machine (the 25 pointer one), I found some vulnerabilities but no way to gain a shell.

### 📝 Writing the report

I used **Notion** to take all my notes while doing the lab and the exam. Previously, I was used to put everything in markdown files, editing them via `vscode` and backup them to Github's private repositories.

In addition to all of its great features, one of the main reason I chose this application is because its faster to copy and paste screenshots from Vmware (via `deepin screenshot`) to a **Notion** web tab. Plus, I could always export my notes as markdown files and / or PDF if I wanted to go back.

By the way, I asked Offsec before doing this. Here is what they respond to me:

![asking offsec about using notion.png](/assets/img/oscp/review/asking_offsec_about_notion.png)

I wanted to use [noraj's OSCP Exam Report Markdown Templates](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown) but having been too slow to start writing the report, I ended up generating a PDF from Notion directly.

<aside style="color:white; display: flex; width: 100%; border-radius: 3px; background: rgb(35, 38, 60) none repeat scroll 0% 0%; padding: 16px 16px 16px 12px;">
💡 You can find my Notion templates for OSCP notes right&nbsp;<a href="https://amplified-maize-ada.notion.site/PWK-OSCP-Templates-11e2f9f66b9e47398cf8ca7d7a9ab8c6">here</a>
</aside>

## ✉️ Getting the certification

Approximately 24 hours after finishing the exam, I received the awaited email telling me I passed the exam from the first attempt!

![Awaited email](/assets/img/oscp/review/awaited_email.png)

> **Note**: The paper certificate should be delivered within 60 days after passing the PWK exam.

# 🛣️ What's next?

- Going through the "Red Team Ops" course form [Zero-Point Security](https://www.zeropointsecurity.co.uk/) and becoming a [CRTO](https://www.zeropointsecurity.co.uk/red-team-ops/overview) (Certified Red Team Operator).
- Completing [TCM](https://academy.tcm-sec.com/) and [Sektor7](https://institute.sektor7.net/) courses.
- Playing with [HackTheBox Pro labs](https://www.hackthebox.com/hacker/pro-labs): **Dante**, **Rastalabs**, **Offshore**, **Cybernetics**, and **APTLabs**.
- [OSEP](https://www.offensive-security.com/pen300-osep/), [OSWE](https://www.offensive-security.com/awae-oswe/), [OSED](https://www.offensive-security.com/exp301-osed/) and [OSWP](https://www.offensive-security.com/wifu-oswp/)
- Improving my Reverse Engineering skills via [Zero2Auto](https://courses.zero2auto.com/) course
- Taking a look at [Blue Team Labs](https://blueteamlabs.online/) and [Cyber Defenders](https://cyberdefenders.org/)
- Joining a CTF team such as [OpenToAll](https://opentoallctf.github.io/)
- ... Master of Pwn 😁

---

# 🎁 Scripts, cheat sheet and templates I would like to share 

One of the things that never ceases to impress me is how much the infosec community shares knowledge: techniques, free tools, free trainings, advices for students as they learn. 

## 📚 Notion templates

[https://amplified-maize-ada.notion.site/PWK-OSCP-Templates-11e2f9f66b9e47398cf8ca7d7a9ab8c6](https://www.notion.so/PWK-OSCP-Templates-11e2f9f66b9e47398cf8ca7d7a9ab8c6)

## 📋 Cheat Sheet + Scripts

- My Personal Cheat Sheet: [https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md#boot2root-cheatsheet](https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md#boot2root-cheatsheet)
- My Buffer overflow exploit skeleton: [https://github.com/amirr0r/notes/blob/master/Infosec/Pwn/shellcode-stack-buffer-overflow-exploit-skeleton.py](https://github.com/amirr0r/notes/blob/master/Infosec/Pwn/shellcode-stack-buffer-overflow-exploit-skeleton.py)
- My Tiny Enumeration `Tmux` Organizer Scripts: [https://github.com/amirr0r/TETOS](https://github.com/amirr0r/TETOS)

---

Thank you for reading me, do not hesitate to hit me on [twitter](https://twitter.com/amirr0r_) if you have any questions!

# Some interesting links

- [0xconda - OSCP Prep Videos](https://www.youtube.com/playlist?list=PLDrNMcTNhhYqZU1ySROli7Oc08mxe1tZR)
- [Rana Khalil- My OSCP Journey — A Review](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/my-oscp-journey-a-review)
- [Andy Li - OSCP Complete Study Guide](https://youtu.be/iheTvk-k55A)
- [John Hammond - 100% OSCP: Offensive Security Certified Professional](https://youtu.be/kdobdnQ2sGw)
- [John Hammond - 2022 OSCP EXAM CHANGES - Goodbye Buffer Overflow, Hello Active Directory](https://www.youtube.com/watch?v=uvqdSGlwEkA)
- [Busra Demir - OSCP Prep Youtube Playlist](https://youtube.com/playlist?list=PLi0kul0fEhZ_NzObRlG2VaOMEqnZuldSF)
- [Retour d'expérience sur les certifications de pentest OSCP et OSWE - Zeecka](https://youtu.be/8MJwhK3BmNU)
- [Acknack - Une expérience OSCP plutôt détaillée...](https://acknak.fr/fr/articles/oscp-retex/)
- [Reddit `r/oscp`](https://www.reddit.com/r/oscp/)