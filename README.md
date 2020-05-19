# BOTection
 Bot Detection by Building Markov Chain Models of Bots Network Behavior

BOTection is a privacy-preserving bot detection system that models the bot network flow behavior as a Markov Chain. Using the state transitions extracted from the Markov chains, we train a Random Forest classifier to first detect network flows produced by bots, and then identify their bot families.
BOTection is content-agnostic and resilient to encryption, relying on high-level network features to model bots' network behavior.  We evaluate our system on a dataset of over 7M malicious flows from 12 botnet families, showing its capability of detecting bots' network traffic with 99.78% F-measure. Notably, due to the modeling of general bot network behavior, BOTection can detect traffic belonging to unseen bot families with an F-measure of 93.03%. BOTection is also robust in classifying a bot family with a 99.09% F-measure score, which is essential in understanding their behavior for effective detection.

![Image of Botection](https://github.com/balahmadi-Ox/BOTection/blob/master/Botection_system.jpg)

## About
This repository contains the code for the paper "[BOTection:  Bot Detection by Building Markov Chain Models of Bots' Network Behavior](https://seclab.bu.edu/people/gianluca/papers/botection-asiaccs2020.pdf)" to Appear in the [15th ACM ASIA Conference on Computer and Communications Security (ACM AsiaCCS'20)](https://asiaccs2020.cs.nthu.edu.tw).


### Prerequisites
In order to convert the PCAPs to Bro/Zeek logs, make sure to install [Zeek/Bro](https://docs.zeek.org/en/current/install/install.html)

## Dataset
In our paper, we used the following datasets:
* [Stratosphere IPS](https://www.stratosphereips.org/datasets-overview)
* [CTU-13](https://www.stratosphereips.org/datasets-ctu13)
* [ISCX Botnet 2014 Dataset](https://www.unb.ca/cic/datasets/botnet.html)

## How to run the code

You can run this code on a python/anaconda environment. 
 - **read the [paper](https://seclab.bu.edu/people/gianluca/papers/botection-asiaccs2020.pdf)**, to understand how the system works!
 - The code is split according to the system modules, described in the paper: 
      * Network Flow Reassembly
      * Connection State Extraction
      * Markov Chain Modeling
      * Detection (Binary Classifier)
      * Family Classification (Multi-Class Classifier)
 - Add you PCAPs to the PCAP folder in Data - benign samples in Benign sub-folder, malicicous in Malicious sub-folder, mix traffic in Mixed subfolder
 
 


## Citation
If you use this repository please cite the paper as follows:
```
@article{alahmadi2019botection,
  title={BOTection: bot detection by building Markov Chain models of bots network behavior},
  author={Alahmadi, B and Mariconti, E and Spolaor, R and Stringhini, G and Martinovic, I},
  year={2019},
  publisher={Association for Computing Machinery}
}

```
## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

