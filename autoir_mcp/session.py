class SSHSession:
    def __init__(self, client=None):
        self.client = client
        self.hijack = False
        self.hijack_output = []
        self.hijack_list = []
        self.user_list = []
        self.group_list = {}
        self.ps = {}
        self.ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]
        self.path = ""
        self.request_success = {}
        self.request_jump = {}
        self.request_others = {}
        self.user_agents = []
        self.safeline_server = False
        self.last_triage_summary = ""
        self.last_triage_type = ""

    def reset_analysis_state(self):
        self.hijack = False
        self.hijack_output = []
        self.hijack_list = []
        self.user_list = []
        self.group_list = {}
        self.ps = {}
        self.ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]
        self.request_success = {}
        self.request_jump = {}
        self.request_others = {}
        self.user_agents = []
        self.last_triage_summary = ""
        self.last_triage_type = ""
