import matplotlib.pyplot as plt
import scipy.stats
import logging
logging.getLogger("kamene.runtime").setLevel(logging.ERROR)
import kamene.all as scapy                # kamene is a part of scapy library compatible with python3.XX versions
from pcapng import FileScanner
import warnings
import random
import time


def find_distribution(data, _type):
    distribution_names = ['alpha', 'arcsine', 'beta', 'cauchy', 'cosine', 'expon', 'pow', 'f',
                          'gamma', 'laplace', 'logistic', 'loglaplace', 'lognorm', 'norm', 'pareto', 'powerlaw',
                          'powernorm','rdist', 'reciprocal', 'semicircular', 't', 'triang', 'uniform', 'weibull_min',
                          'weibull_max']
    distribution_results = []
    params = {}
    for dist_name in distribution_names:
        try:
            dist = getattr(scipy.stats, dist_name)
            param = dist.fit(data)
            params[dist_name] = param
            # Kolmogorov-Smirnov test
            _, p = scipy.stats.kstest(data, dist_name, args=param)
            distribution_results.append((dist_name, p))
        except:
            continue
    # determine optimal distribution
    best_dist, best_p = (max(distribution_results, key=lambda item: item[1]))
    print("Optimal distribution for " + str(_type) + ": " + str(best_dist))
    print("Optimal p value: " + str(best_p))
    print("Parameters for best fit: " + str(params[best_dist]))
    return best_dist, best_p, params[best_dist]


def load_data(filename):
    with open(filename, "rb") as file:
        scanner = list(FileScanner(file))
        packet_sizes = []
        packet_arrival_durations = []
        cnt = 0
        start_timestamp = 0
        for block in scanner:
            if str(block).startswith("<EnhancedPacket"):
                if cnt >= 5000:
                    break
                packet_sizes.append(block.captured_len)
                timestamp = block.timestamp
                packet_arrival_durations.append(timestamp - start_timestamp)
                start_timestamp = timestamp
                cnt += 1
    # first value is an outlier which we discard
    packet_arrival_durations = packet_arrival_durations[1:]
    return packet_sizes, packet_arrival_durations


def scapy_generate(protocol, service, size_params, duration_params, port, timer):
    # packet size per optimal distribution
    if service == "video" or "radio":
        size = int(scipy.stats.cauchy.rvs(loc=size_params[0], scale=size_params[1]))
    elif service == "game":
        size = int(scipy.stats.beta.rvs(a=size_params[0], b=size_params[1], loc=size_params[2], scale=size_params[3]))
    # duration of service per optimal distribution
    if service == "video" or service == "game":
        duration = scipy.stats.arcsine.rvs(loc=duration_params[0], scale=duration_params[1])
        if duration > 30:
            duration = 30
        timer += duration
    elif service == "radio":
        duration = scipy.stats.lognorm.rvs(s=duration_params[0], loc=duration_params[1], scale=duration_params[2])
        if duration > 30:
            duration = 30
        timer += duration

    if size > 65535:
        size = 65000
    data = ''.join(random.choice(lowercase) for _ in range(size))
    data = bytes(data, 'utf-8')
    if protocol == "udp":
        packet = scapy.IP(dst='8.0.0.1')/scapy.UDP(dport=port)/scapy.Raw(data)
    else:
        packet = scapy.IP(dst='8.0.0.1')/scapy.Raw(data)
    scapy.send(packet, verbose=0)
    time.sleep(duration)
    return timer

# class representing a simple Markov chain
class markovChain():

    def __init__(self, transitions1, transitions2, transitions3, start_state):
        self.video_transitions = transitions1
        self.radio_transitions = transitions2
        self.game_transitions = transitions3
        self.current_state = start_state

    def set_current_state(self, state):
        self.current_state = state

    def get_current_state(self):
        return self.current_state

    def get_current_transitions(self):
        if self.current_state == "video":
            return self.video_transitions
        elif self.current_state == "radio":
            return self.radio_transitions
        elif self.current_state == "game":
            return self.game_transitions

    def next_state(self):
        prob1, prob2, prob3 = self.get_current_transitions()
        random_num = random.uniform(0, 1)
        if self.current_state == "video":
            if random_num <= prob1:
                self.set_current_state("video")
            elif prob1 < random_num <= prob2:
                self.set_current_state("radio")
            else:
                self.set_current_state("game")

        elif self.current_state == "radio":
            if random_num <= prob1:
                self.set_current_state("video")
            elif prob1 < random_num <= prob2:
                self.set_current_state("radio")
            else:
                self.set_current_state("game")

        elif self.current_state == "game":
            if random_num <= prob1:
                self.set_current_state("video")
            elif prob1 < random_num <= prob2:
                self.set_current_state("radio")
            else:
                self.set_current_state("game")


if __name__ == '__main__':
    warnings.filterwarnings('error')

    # path to online video data captured with Wireshark
    video_path = "video.pcapng"
    # path to online radio data captured with Wireshark
    radio_path = "radio.pcapng"
    # path to online game data captured with Wireshark
    game_path = "game.pcapng"

    video_packet_sizes, video_packet_timestamps = load_data(video_path)
    avg_video_packet_size = sum(video_packet_sizes) / len(video_packet_sizes)
    avg_video_timestamp = sum(video_packet_timestamps) / len(video_packet_timestamps)
    # print("Avg video packet size: " + str(avg_video_packet_size))
    # print("Avg video packet timestamp: " + str(avg_video_timestamp))
    radio_packet_sizes, radio_packet_timestamps = load_data(radio_path)
    avg_radio_packet_size = sum(radio_packet_sizes) / len(radio_packet_sizes)
    avg_radio_timestamp = sum(radio_packet_timestamps) / len(radio_packet_timestamps)
    # print("Avg radio packet size: " + str(avg_radio_packet_size))
    # print("Avg radio packet timestamp: " + str(avg_radio_timestamp))
    game_packet_sizes, game_packet_timestamps = load_data(game_path)
    avg_game_packet_size = sum(game_packet_sizes) / len(game_packet_sizes)
    avg_game_timestamp = sum(game_packet_timestamps) / len(game_packet_timestamps)
    # print("Avg game packet size: " + str(avg_game_packet_size))
    # print("Avg game packet timestamp: " + str(avg_game_timestamp))
    print("\nVideo:")
    video_packet_size_distribution, _, video_size_params = find_distribution(video_packet_sizes, "Video(packet size)")
    video_timestamp_distribution, _, video_time_params = find_distribution(video_packet_timestamps, "Video(timestamp)")
    print("\nRadio:")
    radio_packet_size_distribution, _, radio_size_params = find_distribution(radio_packet_sizes, "Radio(packet size)")
    radio_timestamp_distribution, _, radio_time_params = find_distribution(radio_packet_timestamps, "Radio(timestamp)")
    print("\nGame:")
    game_packet_size_distribution, _, game_size_params = find_distribution(game_packet_sizes, "Game(packet size)")
    game_timestamp_distribution, _, game_time_params = find_distribution(game_packet_timestamps, "Game(timestamp)")

    ##################################################################

    video_transitions = [0.2, 0.275, 0.525]
    radio_transitions = [0.3, 0.4, 0.3]
    game_transitions = [0.25, 0.2875, 0.4625]

    starting_state = random.choice(["video", "radio", "game"])

    chain = markovChain(video_transitions, radio_transitions, game_transitions, starting_state)

    protocol = "ip"                     # IP or UDP
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'r', 's', 't', 'u',
                 'v', 'z', 'x', 'y', 'w']
    port = 80
    cnt = 0
    video_timer, radio_timer, game_timer = 0, 0, 0

    # Markov chain simulation
    while True:
        print("Current state: '" + chain.get_current_state() + "'")
        curr_state = chain.get_current_state()
        if curr_state == "video":
            video_timer = scapy_generate(protocol, curr_state, video_size_params, video_time_params, port, video_timer)
        elif curr_state == "radio":
            radio_timer = scapy_generate(protocol, curr_state, radio_size_params, radio_time_params, port, radio_timer)
        elif curr_state == "game":
            game_timer = scapy_generate(protocol, curr_state, game_size_params, game_time_params, port, game_timer)
        chain.next_state()
        print("Transition to '" + chain.get_current_state() + "' state")
        cnt += 1
        if cnt == 100:
            break
    total_time = video_timer + game_timer + radio_timer
    print("Empirical probability of retention in 'video' condition: " + str(video_timer/total_time))
    print("Empirical probability of retention in 'radio' condition: : " + str(radio_timer/total_time))
    print("Empirical probability of retention in 'game' condition: : " + str(game_timer/total_time))

    # # lokacija generiranih podataka video usluge snimljenih wiresharkom
    # g_video_path = "generated_video.pcapng"
    # # lokacija generiranih podataka radio usluge snimljenih wiresharkom
    # g_radio_path = "generated_radio.pcapng"
    # # lokacija generiranih podataka game usluge snimljenih wiresharkom
    # g_game_path = "generated_game.pcapng"
    #
    # g_video_packet_sizes, g_video_packet_timestamps = load_data(g_video_path)
    # g_radio_packet_sizes, g_radio_packet_timestamps = load_data(g_radio_path)
    # g_game_packet_sizes, g_game_packet_timestamps = load_data(g_game_path)
    #
    # print("\nGenerirani video:")
    # _, _, _ = find_distribution(g_video_packet_sizes, "Generirani video")
    # _, _, _ = find_distribution(g_video_packet_timestamps, "Generirani video")
    # print("\nGenerirani radio:")
    # _, _, _ = find_distribution(g_radio_packet_sizes, "Generirani radio")
    # _, _, _ = find_distribution(g_radio_packet_timestamps, "Generirani radio")
    # print("\nGenerirana igra:")
    # _, _, _ = find_distribution(g_game_packet_sizes, "Generirana igra")
    # _, _, _ = find_distribution(g_game_packet_timestamps, "Generirana igra")
    #
    # plt.xlim(-0.5, 1)
    # plt.hist(video_packet_timestamps[:2050], alpha=0.5, label="Snimljen promet", bins=80)
    # plt.hist(g_video_packet_timestamps, alpha=0.5, label="Generiran promet", bins=80)
    # plt.legend()
    # plt.show()
