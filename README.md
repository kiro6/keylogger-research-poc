# keylogger-research-poc
Proof of Concept (PoC) demonstrating how cracked software can be used to hide and deploy keyloggers.

> Disclaimer: This project is intended for educational and research purposes only. It demonstrates how malicious actors may embed threats like keyloggers in cracked software to raise awareness and promote defensive security.
Do not use this project to harm, exploit, or compromise systems or users. The authors are not responsible for any misuse of this code or its derivatives.

Content:
- [Methdology](#methdology)
- [Results](#results)
  - [Static Anlaysis](#static-anlaysis)
  - [Dynamic Anlaysis](#dynamic-anlaysis)
- [Conrtibutors](#conrtibutors)
- [Material](#material)
- [License](#license)


## Methdology

<p align="center">
  <img src="/assets/map.png" width="700"/>
</p>



## Results
### Static Anlaysis
⚠️ From 72 engines, *only MaxSecure* flagged the file as `Trojan.Malware.300983.susgen` — a generic heuristic signature that is often considered a false positive in many cases.
<p align="center">
  <img src="/assets/Screenshot_1.png" width="700"/><br>
    <em>VirusTotal Static Scan Result</em>
</p>


<p align="center">
  <img src="/assets/Screenshot_3.png" width="700"/><br>
  <em>MaxSecure False Positive Context</em>
</p>

### Dynamic Anlaysis
✅ No malicious activity was detected during sandbox execution.
<p align="center">
  <img src="/assets/Screenshot_2.png" width="700"/><br>
  <em>VirusTotal Behavior (Dynamic) Scan</em>
</p>

## Conrtibutors
Under supervision of [PhD magabdelaty](https://github.com/magabdelaty)  
- [kiro6](https://github.com/kiro6)  
- [AhmedHosniFahmi](https://github.com/AhmedHosniFahmi)  
- [Mo23fathi](https://github.com/Mo23fathi)  
- [helmii18](https://github.com/helmii18)
- [7amo127](https://github.com/7amo127)
- [yousefelfaham](https://github.com/yousefelfaham)
- [gogofady](https://github.com/gogofady)
- [Topguyy](https://github.com/Topguyy)

## Material
check [docs](/docs) for thesis pdf and powerpoint slides 

## License
This project is licensed under the [MIT License](./LICENSE).
