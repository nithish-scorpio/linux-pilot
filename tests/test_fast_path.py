"""Unit tests for FastPathRouter deterministic routing."""

from pilot.agent.fast_path import FastPathRouter


def test_fast_path_system_info():
    """Verify system info queries route deterministically."""
    res = FastPathRouter.match("What kernel version am I running?")
    assert res is not None
    assert res[0][0] == "system_info"


def test_fast_path_memory_usage():
    """Verify memory inspection queries route deterministically."""
    res = FastPathRouter.match("How much RAM is currently free?")
    assert res is not None
    assert res[0][0] == "memory_usage"


def test_fast_path_disk_usage():
    """Verify disk usage queries route deterministically."""
    res = FastPathRouter.match("Show disk usage on root partition.")
    assert res is not None
    assert res[0][0] == "disk_usage"
    assert res[0][1]["path"] == "/"


def test_fast_path_list_directory():
    """Verify list directory queries route deterministically."""
    res = FastPathRouter.match("List files in the current working directory.")
    assert res is not None
    assert res[0][0] == "list_directory"


def test_fast_path_blocked_queries_rejected():
    """Verify dangerous and blocked commands are never fast-pathed."""
    assert FastPathRouter.match("Run rm -rf / to clean up system.") is None
    assert FastPathRouter.match("Read /etc/shadow password hashes.") is None
    assert FastPathRouter.match("Cat ~/.ssh/id_rsa private key.") is None
    assert FastPathRouter.match("Format hard drive: mkfs.ext4 /dev/sda") is None
    assert FastPathRouter.match("Fork bomb: :(){ :|:& };:") is None


def test_fast_path_ambiguous_delegates_to_llm():
    """Verify ambiguous or complex reasoning requests return None."""
    assert FastPathRouter.match("Why did my custom daemon fail yesterday after upgrade?") is None


def test_fast_path_port_inspection():
    """Verify port inspection queries route deterministically to network_info."""
    res = FastPathRouter.match("Find out which process is using port 8080.")
    assert res is not None
    assert res[0][0] == "network_info"
    assert res[0][1]["port"] == 8080


def test_fast_path_file_rename():
    """Verify file rename queries route deterministically to mv."""
    res = FastPathRouter.match("Rename test.txt to notes.txt")
    assert res is not None
    assert res[0][0] == "execute_command"
    assert res[0][1]["command"] == "mv test.txt notes.txt"


def test_fast_path_environment_variables():
    """Verify environment variable queries route deterministically."""
    res = FastPathRouter.match("Show all environment variables containing PATH.")
    assert res is not None
    assert res[0][0] == "execute_command"
    assert "env | grep -i PATH" in res[0][1]["command"]

    res_single = FastPathRouter.match("What is my path")
    assert res_single is not None
    assert res_single[0][0] == "execute_command"
    assert "printenv PATH" in res_single[0][1]["command"]


def test_fast_path_largest_files():
    """Verify largest files queries route deterministically."""
    res = FastPathRouter.match("find the five largest files in my home directory")
    assert res is not None
    assert res[0][0] == "execute_command"
    assert "find ~ -type f" in res[0][1]["command"]
    assert "head -n 5" in res[0][1]["command"]
