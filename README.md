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
*[ISCX Botnet 2014 Dataset](https://www.unb.ca/cic/datasets/botnet.html)



## Reproduce Evaluation

The code runs inside a Docker container and requires `docker` and `docker-compose` to be installed in your system.

You might be able to make this work on a generic python/anaconda environment with some effort. 
  
To reproduce the evaluation, follow these steps:
 1. **read the [paper](https://arxiv.org/pdf/2004.07088.pdf)** - this is the only way you will understand what you are doing
 1. Clone this repository
 1. download the [dataset](https://ora.ox.ac.uk/objects/uuid:1a04e852-e7e1-4981-aa83-f2e729371484) used in the paper, unzip the archive and place the downloaded `videos` folder in `seeing-red/data/`
 1. build and start the container by running `docker-compose up -d`
 1. attach to the container with `docker attach seeingred_er`
 1. in the container, `cd /home/code` and run the entire signal analysis pipeline with `python signal_run_all.py`

Results will be produced in several subfolders in `seeing-red/data/`.

## Citation
If you use this repository please cite the paper as follows:
```
@inproceedings{lovisotto2020seeing,
  title={Seeing Red: PPG Biometrics Using Smartphone Cameras},
  author={Lovisotto, Giulio and Turner, Henry and Eberz, Simon and Martinovic, Ivan},
  booktitle={IEEE 15th Computer Society Workshop on Biometrics},
  year={2020}
}
```
## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* etc

