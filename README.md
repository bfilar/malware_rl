# MalwareRL
> Malware Bypass Research using Reinforcement Learning

## Background
This is a malware manipulation environment using OpenAI's gym environments. The core idea is based on paper "Learning to Evade Static PE Machine Learning Malware Models via Reinforcement Learning"
([paper](https://arxiv.org/abs/1801.08917)). I am extending the original repo because:
1. It is no longer maintained
2. It uses Python2 and an outdated version of LIEF
3. I wanted to integrate new Malware gym environments and additional manipulations

Over the past three years there have been breakthrough open-source projects published in the security ML space. In particular, [Ember](https://github.com/endgameinc/ember) (Endgame Malware BEnchmark for Research) ([paper](https://arxiv.org/abs/1804.04637)) and MalConv: Malware detection by eating a whole exe ([paper](https://arxiv.org/abs/1710.09435)) have provided security researchers the ability to develop sophisticated, reproducible models that emulate features/techniques found in NGAVs.

## MalwareRL Gym Environment
MalwareRL exposes `gym` environments for both Ember and MalConv to allow researchers to develop Reinforcement Learning agents to bypass Malware Classifiers. Actions include a variety of non-breaking (e.g. binaries will still execute) modifications to the PE header, sections, imports and overlay and are listed below.

### Action Space
```
ACTION_TABLE = {
    'modify_machine_type': 'modify_machine_type',
    'pad_overlay': 'pad_overlay',
    'append_benign_data_overlay': 'append_benign_data_overlay',
    'append_benign_binary_overlay': 'append_benign_binary_overlay',
    'add_bytes_to_section_cave': 'add_bytes_to_section_cave',
    'add_section_strings': 'add_section_strings',
    'add_section_benign_data': 'add_section_benign_data',
    'add_strings_to_overlay': 'add_strings_to_overlay',
    'add_imports': 'add_imports',
    'rename_section': 'rename_section',
    'remove_debug': 'remove_debug',
    'modify_optional_header': 'modify_optional_header',
    'modify_timestamp': 'modify_timestamp',
    'break_optional_header_checksum': 'break_optional_header_checksum',
    'upx_unpack': 'upx_unpack',
    'upx_pack': 'upx_pack'
}
```

### Observation Space
The `observation_space` of the `gym` environments are an array representing the feature vector. For ember this is `numpy.array == 2381` and malconv `numpy.array == 1024**2`. The MalConv gym presents an opportunity to try RL techniques to generalize learning across large State Spaces.

### Agents
A baseline agent `RandomAgent` is provided to demonstrate how to interact w/ `gym` environments and expected output. This agent attempts to evade the classifier by randomly selecting an action. This process is repeated up to the length of a game (e.g. 50 mods). If the modifed binary scores below the classifier threshold we register it as an evasion. In a lot of ways the `RandomAgent` acts as a fuzzer trying a bunch of actions with no regard to minimizing the modifications of the resulting binary.

Additional agents will be developed and made available (both model and code) in the coming weeks.

**Table 1:** _Evasion Rate against Ember Holdout Dataset_*
| gym | agent | evasion_rate | avg_ep_len |
| --- | ----- | ------------ | ---------- |
| ember | RandomAgent | 89.2% | 8.2
| malconv | RandomAgent | 88.5% | 16.33

\
\* _250 random samples_

## Setup
To get `malware_rl` up and running you will need the follow external dependencies:
- [LIEF](https://lief.quarkslab.com/)
- [Ember](https://github.com/Azure/2020-machine-learning-security-evasion-competition/blob/master/defender/defender/models/ember_model.txt.gz), [Malconv](https://github.com/endgameinc/ember/blob/master/malconv/malconv.h5) and [SOREL-20M](https://github.com/sophos-ai/SOREL-20M) models. All of these then need to be placed into the `malware_rl/envs/utils/` directory.
  > The SOREL-20M model requires use of the `aws-cli` in order to get. When accessing the AWS S3 bucket, look in the `sorel-20m-model/checkpoints/lightGBM` folder and fish out any of the models in the `seed` folders. The model file will need to be renamed to `sorel.model` and placed into `malware_rl/envs/utils` alongside the other models.
- UPX has been added to support pack/unpack modifications. Download the binary [here](https://upx.github.io/) and place in the `malware_rl/envs/controls` directory.
- Benign binaries - a small set of "trusted" binaries (e.g. grabbed from base Windows installation) you can download some via MSFT website ([example](https://download.microsoft.com/download/a/c/1/ac1ac039-088b-4024-833e-28f61e01f102/NETFX1.1_bootstrapper.exe)). Store these binaries in `malware_rl/envs/controls/trusted`
- Run `strings` command on those binaries and save the output as `.txt` files in `malware_rl/envs/controls/good_strings`
- Download a set of malware from VirusShare or VirusTotal. I just used a list of hashes from the Ember dataset

**Note:** The helper script `download_deps.py` can be used as a quickstart to get most of the key dependencies setup.

I used a [conda](https://docs.conda.io/en/latest/) env set for Python3.7:

`conda create -n malware_rl python=3.7`

Finally install the Python3 dependencies in the `requirements.txt`.

`pip3 install -r requirements.txt`

## References
The are a bunch of good papers/blog posts on manipulating binaries to evade ML classifiers. I compiled a few that inspired portions of this project below. Also, I have inevitably left out other pertinent reseach, so if there is something that should be in here let me know in an Git Issue or hit me up on Twitter ([@filar](https://twitter.com/filar)).
### Papers
- Demetrio, Luca, et al. "Efficient Black-box Optimization of Adversarial Windows Malware with Constrained Manipulations." arXiv preprint arXiv:2003.13526 (2020). ([paper](https://arxiv.org/abs/2003.13526))
- Demetrio, Luca, et al. "Adversarial EXEmples: A Survey and Experimental Evaluation of Practical Attacks on Machine Learning for Windows Malware Detection." arXiv preprint arXiv:2008.07125 (2020). ([paper](https://arxiv.org/abs/2008.07125))
- Song, Wei, et al. "Automatic Generation of Adversarial Examples for Interpreting Malware Classifiers." arXiv preprint arXiv:2003.03100 (2020).
 ([paper](https://arxiv.org/abs/2003.03100))
- Suciu, Octavian, Scott E. Coull, and Jeffrey Johns. "Exploring adversarial examples in malware detection." 2019 IEEE Security and Privacy Workshops (SPW). IEEE, 2019. ([paper](https://arxiv.org/abs/1810.08280))
- Fleshman, William, et al. "Static malware detection & subterfuge: Quantifying the robustness of machine learning and current anti-virus." 2018 13th International Conference on Malicious and Unwanted Software (MALWARE). IEEE, 2018. ([paper](https://arxiv.org/abs/1806.04773))
- Pierazzi, Fabio, et al. "Intriguing properties of adversarial ML attacks in the problem space." 2020 IEEE Symposium on Security and Privacy (SP). IEEE, 2020. ([paper/code](https://s2lab.kcl.ac.uk/projects/intriguing/))
- Fang, Zhiyang, et al. "Evading anti-malware engines with deep reinforcement learning." IEEE Access 7 (2019): 48867-48879. ([paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8676031))

### Blog Posts
- [Evading Machine Learning Malware Classifiers: for fun and profit!](https://towardsdatascience.com/evading-machine-learning-malware-classifiers-ce52dabdb713)
- [Cylance, I Kill You!](https://skylightcyber.com/2019/07/18/cylance-i-kill-you/)
- [Machine Learning Security Evasion Competition 2020](https://msrc-blog.microsoft.com/2020/06/01/machine-learning-security-evasion-competition-2020-invites-researchers-to-defend-and-attack/)
- [ML evasion contest – the AV tester’s perspective](https://www.mrg-effitas.com/research/machine-learning-evasion-contest-the-av-testers-perspective/)

### Talks
- 42: The answer to life the universe and everything offensive security by Will Pearce, Nick Landers ([slides](https://github.com/moohax/Talks/blob/master/slides/DerbyCon19.pdf))
- Bot vs. Bot: Evading Machine Learning Malware Detection by Hyrum Anderson ([slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Anderson-Bot-Vs-Bot-Evading-Machine-Learning-Malware-Detection.pdf))
- Trying to Make Meterpreter into an Adversarial Example by Andy Applebaum ([slides](https://www.camlis.org/2019/talks/applebaum))
