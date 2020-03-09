package testutil

import (
	"github.com/kevlar1818/duc/artifact"
	"io/ioutil"
	"os"
	"path"
)

// ArtifactWorkspaceStatus enumerates the states of an Artifact as it pertains to the workspace
type ArtifactWorkspaceStatus int

const (
	// IsAbsent means that the artifact is absent from the workspace
	IsAbsent ArtifactWorkspaceStatus = iota
	// IsRegularFile means that the artifact is present as a regular file in the workspace
	// TODO expand this to ContentsMatch, ContentsDiffer
	IsRegularFile
	// IsLink means that the artifact is present as a link in the workspace
	IsLink
)

// TempDirs holds a pair of cache and workspace directory paths for integration testing.
type TempDirs struct {
	CacheDir string
	WorkDir  string
}

// CreateTempDirs creates a DUC cache and workspace in the OS temp FS.
func CreateTempDirs() (dirs TempDirs, err error) {
	dirs.CacheDir, err = ioutil.TempDir("", "duc_cache")
	if err != nil {
		return
	}
	dirs.WorkDir, err = ioutil.TempDir("", "duc_wspace")
	if err != nil {
		os.RemoveAll(dirs.CacheDir)
		return
	}
	return
}

// CreateArtifactTestCase sets up an integration test environment with a single
// artifact according the arguments provided. The bool argument specifies whether the
// artifact is present in the cache.
func CreateArtifactTestCase(inCache bool, wspaceStatus ArtifactWorkspaceStatus) (dirs TempDirs, art artifact.Artifact, err error) {
	dirs, err = CreateTempDirs()
	if err != nil {
		return
	}

	fileContents := []byte("Hello, World!")

	art = artifact.Artifact{
		Checksum: "0a0a9f2a6772942557ab5355d76af442f8f65e01",
		Path:     "hello.txt",
	}

	if inCache {
		fileCacheDir := path.Join(dirs.CacheDir, art.Checksum[:2])
		fileCachePath := path.Join(fileCacheDir, art.Checksum[2:])

		if err = os.Mkdir(fileCacheDir, 0755); err != nil {
			return
		}
		if err = ioutil.WriteFile(fileCachePath, fileContents, 0444); err != nil {
			return
		}
	}

	fileWorkspacePath := path.Join(dirs.WorkDir, art.Path)
	switch wspaceStatus {
	case IsRegularFile:
		if err = ioutil.WriteFile(fileWorkspacePath, fileContents, 0644); err != nil {
			return
		}
	case IsLink: // TODO
	}
	return
}