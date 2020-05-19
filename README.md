# BOTection
 Bot Detection by Building Markov Chain Models of Bots Network Behavior

BOTection is a privacy-preserving bot detection system that models the bot network flow behavior as a Markov Chain. Using the state transitions extracted from the Markov chains, we train a Random Forest classifier to first detect network flows produced by bots, and then identify their bot families.
BOTection is content-agnostic and resilient to encryption, relying on high-level network features to model bots' network behavior.  We evaluate our system on a dataset of over 7M malicious flows from 12 botnet families, showing its capability of detecting bots' network traffic with 99.78% F-measure. Notably, due to the modeling of general bot network behavior, BOTection can detect traffic belonging to unseen bot families with an F-measure of 93.03%. BOTection is also robust in classifying a bot family with a 99.09% F-measure score, which is essential in understanding their behavior for effective detection.

![Image of Botection](https://github.com/balahmadi-Ox/BOTection/blob/master/Botection_system.jpg)

## About
This repository contains the code for the paper "[BOTection:  Bot Detection by Building Markov Chain Models of Bots' Network Behavior](https://seclab.bu.edu/people/gianluca/papers/botection-asiaccs2020.pdf)" to Appear in the [15th ACM ASIA Conference on Computer and Communications Security (ACM AsiaCCS'20)](https://asiaccs2020.cs.nthu.edu.tw).

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them

```
Give examples
```

### Installing

A step by step series of examples that tell you how to get a development env running

Say what the step will be

```
Give the example
```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* etc

