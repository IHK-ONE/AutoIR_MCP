class SSHSession:
    def __init__(self, client=None):
        self.client = client
        self.safeline_available = False
        self.reset_analysis_state()

    def reset_analysis_state(self):
        self.hijack = False
        self.hijack_output = []
        self.user_list = []
        self.group_list = {}
        self.ps = {}
        self.ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]
