#!/usr/bin/env python3
from contextlib import closing
import multiprocessing
import os
import os.path
import re
import socket
import subprocess
import sys
import traceback
import urllib.parse
import urllib3
import bs4
import dulwich.index
import dulwich.objects
import dulwich.pack
import dulwich.repo
import requests
import socks
from requests_pkcs12 import Pkcs12Adapter

# Set of types for progress callback: (completed_tasks, total_tasks, current_file_name)
# Callback signature: callback(completed: int, total: int, current_file: str)

def isHtml(response):
    """ Return True if the response is a HTML webpage """
    return (
        "Content-Type" in response.headers
        and "text/html" in response.headers["Content-Type"]
    )

def isSafePath(path):
    """ Prevent directory traversal attacks """
    if path.startswith("/"):
        return False
    safePath = os.path.expanduser("~")
    return (
        os.path.commonpath(
            (os.path.realpath(os.path.join(safePath, path)), safePath)
        )
        == safePath
    )

def getIndexedFiles(response):
    """ Return all the files in the directory index webpage """
    html = bs4.BeautifulSoup(response.text, "html.parser")
    files = []
    for link in html.find_all("a"):
        url = urllib.parse.urlparse(link.get("href"))
        if (
            url.path
            and isSafePath(url.path)
            and not url.scheme
            and not url.netloc
        ):
            files.append(url.path)
    return files

def verifyResponse(response):
    if response.status_code != 200:
        return (
            False,
            "[-] %s/%s responded with status code {code}\n".format(
                code=response.status_code
            ),
        )
    elif (
        "Content-Length" in response.headers
        and response.headers["Content-Length"] == 0
    ):
        return False, "[-] %s/%s responded with a zero-length body\n"
    elif (
        "Content-Type" in response.headers
        and "text/html" in response.headers["Content-Type"]
    ):
        return False, "[-] %s/%s responded with HTML\n"
    else:
        return True, True

def createIntermediateDirs(path):
    """ Create intermediate directories, if necessary """
    dirname, basename = os.path.split(path)
    if dirname and not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except FileExistsError:
            pass  # race condition

def getReferencedSha1(objFile):
    """ Return all the referenced SHA1 in the given object file """
    objs = []
    if isinstance(objFile, dulwich.objects.Commit):
        objs.append(objFile.tree.decode())
        for parent in objFile.parents:
            objs.append(parent.decode())
    elif isinstance(objFile, dulwich.objects.Tree):
        for item in objFile.iteritems():
            objs.append(item.sha.decode())
    elif isinstance(objFile, dulwich.objects.Blob):
        pass
    elif isinstance(objFile, dulwich.objects.Tag):
        pass
    return objs

class Worker(multiprocessing.Process):
    """ Worker for processTasks """
    def __init__(self, pendingTasks, tasksDone, args):
        super().__init__()
        self.daemon = True
        self.pendingTasks = pendingTasks
        self.tasksDone = tasksDone
        self.args = args

    def run(self):
        self.init(*self.args)
        while True:
            try:
                task = self.pendingTasks.get(block=True)
                if task is None:  # end signal
                    return
                try:
                    result = self.doTask(task, *self.args)
                except KeyboardInterrupt:
                    return
                except Exception:
                    # Silenced verbose error output for cleaner UI
                    result = []
                assert isinstance(
                    result, list
                ), "doTask() should return a list of tasks"
                self.tasksDone.put(result)
            except KeyboardInterrupt:
                return

    def init(self, *args):
        raise NotImplementedError

    def doTask(self, task, *args):
        raise NotImplementedError

def processTasks(initialTasks, workerClass, jobs, args=(), tasksDone=None, progressCallback=None):
    """ Process tasks in parallel """
    if not initialTasks:
        return

    tasksSeen = set(tasksDone) if tasksDone else set()
    pendingTasksQueue = multiprocessing.Queue()
    tasksDoneQueue = multiprocessing.Queue()
    numPendingTasks = 0

    for task in initialTasks:
        assert task is not None
        if task not in tasksSeen:
            pendingTasksQueue.put(task)
            numPendingTasks += 1
            tasksSeen.add(task)

    processes = [workerClass(pendingTasksQueue, tasksDoneQueue, args) for _ in range(jobs)]
    for p in processes:
        p.start()
    
    totalTasksProcessed = 0
    totalKnownTasks = numPendingTasks

    try:
        while numPendingTasks > 0:
            taskResult = tasksDoneQueue.get(block=True)
            numPendingTasks -= 1
            totalTasksProcessed += 1
            
            # Determine current file from last task result? 
            # Actually worker doesn't return which task completed easily here without modifying structure much.
            # But we can update progress count.
            if progressCallback:
                # We don't have exact filename easily available here without bigger change, 
                # but we can send generic update
                progressCallback(totalTasksProcessed, totalKnownTasks, "")

            for task in taskResult:
                assert task is not None
                if task not in tasksSeen:
                    pendingTasksQueue.put(task)
                    numPendingTasks += 1
                    totalKnownTasks += 1
                    tasksSeen.add(task)
    except KeyboardInterrupt:
        # Stop everything
        for p in processes:
            p.terminate()
            p.join()
        return

    for _ in range(jobs):
        pendingTasksQueue.put(None)
    for p in processes:
        p.join()

class DownloadWorker(Worker):
    """ Download a list of files """
    def init(self, url, directory, retry, timeout, httpHeaders, clientCertP12=None, clientCertP12Password=None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = httpHeaders
        if clientCertP12:
            self.session.mount(url, Pkcs12Adapter(pkcs12_filename=clientCertP12, pkcs12_password=clientCertP12Password))
        else:
            self.session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))

    def doTask(self, filepath, url, directory, retry, timeout, httpHeaders, clientCertP12=None, clientCertP12Password=None):
        if os.path.isfile(os.path.join(directory, filepath)):
            return []
        
        try:
            with closing(
                self.session.get(
                    "%s/%s" % (url, filepath),
                    allow_redirects=False,
                    stream=True,
                    timeout=timeout,
                )
            ) as response:
                valid, errorMessage = verifyResponse(response)
                if not valid:
                    return []
                abspath = os.path.abspath(os.path.join(directory, filepath))
                createIntermediateDirs(abspath)
                with open(abspath, "wb") as f:
                    for chunk in response.iter_content(4096):
                        f.write(chunk)
                return []
        except Exception:
            return []

class RecursiveDownloadWorker(DownloadWorker):
    """ Download a directory recursively """
    def doTask(self, filepath, url, directory, retry, timeout, httpHeaders):
        if os.path.isfile(os.path.join(directory, filepath)):
            return []
            
        try:
            with closing(
                self.session.get(
                    "%s/%s" % (url, filepath),
                    allow_redirects=False,
                    stream=True,
                    timeout=timeout,
                )
            ) as response:
                if (
                    response.status_code in (301, 302)
                    and "Location" in response.headers
                    and response.headers["Location"].endswith(filepath + "/")
                ):
                    return [filepath + "/"]
                if filepath.endswith("/"):  # directory index
                    if isHtml(response):
                        return [
                            filepath + filename
                            for filename in getIndexedFiles(response)
                        ]
                    return []
                else:  # file
                    valid, errorMessage = verifyResponse(response)
                    if not valid:
                        return []
                    abspath = os.path.abspath(os.path.join(directory, filepath))
                    createIntermediateDirs(abspath)
                    with open(abspath, "wb") as f:
                        for chunk in response.iter_content(4096):
                            f.write(chunk)
                    return []
        except Exception:
            return []

class FindRefsWorker(DownloadWorker):
    """ Find refs/ """
    def doTask(self, filepath, url, directory, retry, timeout, httpHeaders, clientCertP12=None, clientCertP12Password=None):
        try:
            response = self.session.get(
                "%s/%s" % (url, filepath), allow_redirects=False, timeout=timeout
            )
            valid, errorMessage = verifyResponse(response)
            if not valid:
                return []
            abspath = os.path.abspath(os.path.join(directory, filepath))
            createIntermediateDirs(abspath)
            with open(abspath, "w") as f:
                f.write(response.text)
            tasks = []
            for ref in re.findall(
                r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)", response.text
            ):
                ref = ref[0]
                if not ref.endswith("*") and isSafePath(ref):
                    tasks.append(".git/%s" % ref)
                    tasks.append(".git/logs/%s" % ref)
            return tasks
        except Exception:
            return []

class FindObjectsWorker(DownloadWorker):
    """ Find objects """
    def doTask(self, obj, url, directory, retry, timeout, httpHeaders, clientCertP12=None, clientCertP12Password=None):
        filepath = ".git/objects/%s/%s" % (obj[:2], obj[2:])
        if os.path.isfile(os.path.join(directory, filepath)):
            pass
        else:
            try:
                response = self.session.get(
                    "%s/%s" % (url, filepath),
                    allow_redirects=False,
                    timeout=timeout,
                )
                valid, errorMessage = verifyResponse(response)
                if not valid:
                    return []
                abspath = os.path.abspath(os.path.join(directory, filepath))
                createIntermediateDirs(abspath)
                with open(abspath, "wb") as f:
                    f.write(response.content)
            except Exception:
                return []
        
        try:
            abspath = os.path.abspath(os.path.join(directory, filepath))
            objFile = dulwich.objects.ShaFile.from_path(abspath)
            return getReferencedSha1(objFile)
        except Exception:
            return []

def sanitizeFile(filepath):
    """ Inplace comment out possibly unsafe lines based on regex """
    if not os.path.isfile(filepath):
        return
    UNSAFE=r"^\s*fsmonitor|sshcommand|askpass|editor|pager"
    with open(filepath, 'r+') as f:
        content = f.read()
        modifiedContent = re.sub(UNSAFE, r'# \g<0>', content, flags=re.IGNORECASE)
        if content != modifiedContent:
            f.seek(0)
            f.write(modifiedContent)

def fetchGit(url, directory, jobs, retry, timeout, httpHeaders, clientCertP12=None, clientCertP12Password=None, progressCallback=None):
    """ Dump a git repository into the output directory """
    if not os.path.exists(directory):
        os.makedirs(directory)
        
    session = requests.Session()
    session.verify = False
    session.headers = httpHeaders
    if clientCertP12:
        session.mount(url, Pkcs12Adapter(pkcs12_filename=clientCertP12, pkcs12_password=clientCertP12Password))
    else:
        session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))
    
    # find base url
    url = url.rstrip("/")
    if url.endswith("HEAD"):
        url = url[:-4]
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    # check for /.git/HEAD
    try:
        response = session.get(
            "%s/.git/HEAD" % url, 
            timeout=timeout, 
            allow_redirects=False
        )
        valid, errorMessage = verifyResponse(response)
        if not valid:
            return 1
        elif not re.match(r"^(ref:.*|[0-9a-f]{40}$)", response.text.strip()):
            return 1
    except Exception:
        return 1

    # set up environment to ensure proxy usage
    environment = os.environ.copy()
    configuredProxy = socks.getdefaultproxy()
    if configuredProxy is not None:
        proxyTypes = ["http", "socks4h", "socks5h"]
        environment["ALL_PROXY"] = f"http.proxy={proxyTypes[configuredProxy[0]]}://{configuredProxy[1]}:{configuredProxy[2]}"

    # check for directory listing
    try:
        response = session.get("%s/.git/" % url, allow_redirects=False)
        if (
            response.status_code == 200
            and isHtml(response)
            and "HEAD" in getIndexedFiles(response)
        ):
            processTasks(
                [".git/", ".gitignore"],
                RecursiveDownloadWorker,
                jobs,
                args=(url, directory, retry, timeout, httpHeaders),
                progressCallback=progressCallback
            )
            
            # Use absolute path for config
            configPath = os.path.join(directory, ".git", "config")
            sanitizeFile(configPath)
            
            # Run git checkout in the target directory without changing global CWD
            subprocess.check_call(
                ["git", "checkout", "."], 
                cwd=directory,
                env=environment, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            return 0
    except Exception:
        pass # proceed to non-listing method

    # no directory listing - common files
    tasks = [
        ".gitignore",
        ".git/COMMIT_EDITMSG",
        ".git/description",
        ".git/hooks/applypatch-msg.sample",
        ".git/hooks/commit-msg.sample",
        ".git/hooks/post-commit.sample",
        ".git/hooks/post-receive.sample",
        ".git/hooks/post-update.sample",
        ".git/hooks/pre-applypatch.sample",
        ".git/hooks/pre-commit.sample",
        ".git/hooks/pre-push.sample",
        ".git/hooks/pre-rebase.sample",
        ".git/hooks/pre-receive.sample",
        ".git/hooks/prepare-commit-msg.sample",
        ".git/hooks/update.sample",
        ".git/index",
        ".git/info/exclude",
        ".git/objects/info/packs",
    ]
    processTasks(
        tasks,
        DownloadWorker,
        jobs,
        args=(url, directory, retry, timeout, httpHeaders, clientCertP12, clientCertP12Password),
        progressCallback=progressCallback
    )

    # find refs
    tasks = [
        ".git/FETCH_HEAD",
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/config",
        ".git/info/refs",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/main",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/heads/staging",
        ".git/logs/refs/heads/production",
        ".git/logs/refs/heads/development",
        ".git/logs/refs/remotes/origin/HEAD",
        ".git/logs/refs/remotes/origin/main",
        ".git/logs/refs/remotes/origin/master",
        ".git/logs/refs/remotes/origin/staging",
        ".git/logs/refs/remotes/origin/production",
        ".git/logs/refs/remotes/origin/development",
        ".git/logs/refs/stash",
        ".git/packed-refs",
        ".git/refs/heads/main",
        ".git/refs/heads/master",
        ".git/refs/heads/staging",
        ".git/refs/heads/production",
        ".git/refs/heads/development",
        ".git/refs/remotes/origin/HEAD",
        ".git/refs/remotes/origin/main",
        ".git/refs/remotes/origin/master",
        ".git/refs/remotes/origin/staging",
        ".git/refs/remotes/origin/production",
        ".git/refs/remotes/origin/development",
        ".git/refs/stash",
        ".git/refs/wip/wtree/refs/heads/main",
        ".git/refs/wip/wtree/refs/heads/master",
        ".git/refs/wip/wtree/refs/heads/staging",
        ".git/refs/wip/wtree/refs/heads/production",
        ".git/refs/wip/wtree/refs/heads/development",
        ".git/refs/wip/index/refs/heads/main",
        ".git/refs/wip/index/refs/heads/master",
        ".git/refs/wip/index/refs/heads/staging",
        ".git/refs/wip/index/refs/heads/production",
        ".git/refs/wip/index/refs/heads/development"
    ]

    processTasks(
        tasks,
        FindRefsWorker,
        jobs,
        args=(url, directory, retry, timeout, httpHeaders, clientCertP12, clientCertP12Password),
        progressCallback=progressCallback
    )

    # find packs
    tasks = []
    infoPacksPath = os.path.join(
        directory, ".git", "objects", "info", "packs"
    )
    if os.path.exists(infoPacksPath):
        try:
            with open(infoPacksPath, "r") as f:
                infoPacks = f.read()

            for sha1 in re.findall(r"pack-([a-f0-9]{40})\.pack", infoPacks):
                tasks.append(".git/objects/pack/pack-%s.idx" % sha1)
                tasks.append(".git/objects/pack/pack-%s.pack" % sha1)
        except Exception:
            pass

    processTasks(
        tasks,
        DownloadWorker,
        jobs,
        args=(url, directory, retry, timeout, httpHeaders, clientCertP12, clientCertP12Password),
        progressCallback=progressCallback
    )

    # find objects
    objs = set()
    packedObjs = set()

    files = [
        os.path.join(directory, ".git", "packed-refs"),
        os.path.join(directory, ".git", "info", "refs"),
        os.path.join(directory, ".git", "FETCH_HEAD"),
        os.path.join(directory, ".git", "ORIG_HEAD"),
    ]
    for dirpath, _, filenames in os.walk(
        os.path.join(directory, ".git", "refs")
    ):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    for dirpath, _, filenames in os.walk(
        os.path.join(directory, ".git", "logs")
    ):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))

    for filepath in files:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, "r") as f:
                content = f.read()
            for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
                obj = obj[1]
                objs.add(obj)
        except Exception:
            pass

    indexPath = os.path.join(directory, ".git", "index")
    if os.path.exists(indexPath):
        try:
            index = dulwich.index.Index(indexPath)
            for entry in index.iterobjects():
                objs.add(entry[1].decode())
        except Exception:
            pass

    packFileDir = os.path.join(directory, ".git", "objects", "pack")
    if os.path.isdir(packFileDir):
        for filename in os.listdir(packFileDir):
            if filename.startswith("pack-") and filename.endswith(".pack"):
                try:
                    packDataPath = os.path.join(packFileDir, filename)
                    packIdxPath = os.path.join(
                        packFileDir, filename[:-5] + ".idx"
                    )
                    packData = dulwich.pack.PackData(packDataPath)
                    packIdx = dulwich.pack.load_pack_index(packIdxPath)
                    pack = dulwich.pack.Pack.from_objects(packData, packIdx)
                    for objFile in pack.iterobjects():
                        packedObjs.add(objFile.sha().hexdigest())
                        objs |= set(getReferencedSha1(objFile))
                except Exception:
                    pass

    # fetch all objects
    processTasks(
        objs,
        FindObjectsWorker,
        jobs,
        args=(url, directory, retry, timeout, httpHeaders, clientCertP12, clientCertP12Password),
        tasksDone=packedObjs,
        progressCallback=progressCallback
    )

    # git checkout
    # Do NOT chdir. Use cwd argument.
    configPath = os.path.join(directory, ".git", "config")
    sanitizeFile(configPath)
    # ignore errors
    subprocess.call(
        ["git", "checkout", "."], 
        stderr=open(os.devnull, "wb"),
        stdout=open(os.devnull, "wb"),
        env=environment,
        cwd=directory
    )
    return 0

def getAllCommits(repo):
    """ Yield all commit objects from the repository """
    for sha in repo.object_store:
        try:
            obj = repo[sha]
            if isinstance(obj, dulwich.objects.Commit):
                yield obj
        except Exception:
            pass

def extractCommit(repo, commit, outputDir):
    """ Extract files from a specific commit """
    commitSha = commit.id.decode()
    commitDir = os.path.join(outputDir, "extracted_%s" % commitSha)
    
    if not os.path.exists(commitDir):
        os.makedirs(commitDir)
    
    # Write commit meta
    try:
        with open(os.path.join(commitDir, "commit-meta.txt"), "w") as f:
            f.write("Author: %s\n" % commit.author.decode(errors='replace'))
            f.write("Committer: %s\n" % commit.committer.decode(errors='replace'))
            f.write("Time: %s\n" % commit.commit_time)
            f.write("Message: %s\n" % commit.message.decode(errors='replace'))
    except Exception:
        pass

    # Walk the tree
    q = [(commit.tree, ".")]
    
    while q:
        treeSha, currentPath = q.pop(0)
        try:
            tree = repo[treeSha]
            if not isinstance(tree, dulwich.objects.Tree):
                continue
                
            for entry in tree.items():
                name = entry.path.decode(errors='replace')
                mode = entry.mode
                sha = entry.sha
                
                path = os.path.join(currentPath, name)
                
                # Check safe path for extraction
                if not isSafePath(path):
                    continue
                
                fullPath = os.path.join(commitDir, path)
                
                # Directory (mode 040000 = 16384)
                if mode & 0o040000:
                    if not os.path.exists(fullPath):
                        os.makedirs(fullPath)
                    q.append((sha, path))
                # Blob (regular file)
                else:
                    try:
                        blob = repo[sha]
                        if isinstance(blob, dulwich.objects.Blob):
                            # Ensure parent dir exists
                            parentDir = os.path.dirname(fullPath)
                            if not os.path.exists(parentDir):
                                os.makedirs(parentDir)
                                
                            with open(fullPath, "wb") as f:
                                f.write(blob.data)
                    except KeyError:
                        pass
        except KeyError:
            pass

def extractAllCommits(directory):
    """ Extract all commits found in the .git directory. Returns count of commits extracted. """
    count = 0
    try:
        repo = dulwich.repo.Repo(directory)
    except Exception:
        return 0
    for commit in getAllCommits(repo):
        extractCommit(repo, commit, directory)
        count += 1
    return count

def dumpAndExtract(url, directory, jobs=10, retry=3, timeout=3, userAgent="Mozilla/5.0", progressCallback=None):
    """
    Main entry point for module usage.
    Dumps the git repo and extracts commits.
    """
    httpHeaders = {"User-Agent": userAgent}
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Ensure absolute path for safety
    directory = os.path.abspath(directory)

    try:
        retCode = fetchGit(
            url,
            directory,
            jobs,
            retry,
            timeout,
            httpHeaders,
            progressCallback=progressCallback
        )
        
        if retCode == 0:
            # We must pass the directory where .git is located
            return extractAllCommits(directory)
            
    except Exception:
        # Don't print stack trace here, let caller handle or ignore
        pass
    return 0
