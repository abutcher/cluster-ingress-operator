// Code generated by go-bindata. DO NOT EDIT.
// sources:
// test/assets/app-ingress/deployment.yaml (319B)
// test/assets/app-ingress/namespace.yaml (123B)
// test/assets/app-ingress/route.yaml (215B)
// test/assets/app-ingress/service.yaml (186B)

package manifests

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes  []byte
	info   os.FileInfo
	digest [sha256.Size]byte
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _testAssetsAppIngressDeploymentYaml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x6c\x8f\xb1\x4e\x83\x31\x0c\x84\xf7\x3c\xc5\xbd\xc0\xaf\xaa\x6b\x66\x46\x66\x76\x93\x1e\xfd\x23\x9c\xc4\x8a\x0d\x12\x6f\x8f\x42\x4b\xc5\x2f\x71\x93\xed\xd3\x77\x3a\xbf\xd7\x7e\xc9\x78\xa2\xe9\xf8\x6a\xec\x91\xc4\xea\x0b\xa7\xd7\xd1\x33\xc4\xcc\x4f\x9f\xe7\xd4\x18\x72\x91\x90\x9c\x80\x2e\x8d\x3f\xce\x7d\x76\x93\xc2\x8c\xa2\x1f\x1e\x9c\x5b\xed\xd7\x49\xf7\x2d\xe8\x91\xdc\x58\x16\x33\x69\x5a\x8b\x78\xc6\x39\x01\x4e\x65\x89\x31\x97\x03\x34\x89\xb2\x3f\xcb\x2b\xd5\x6f\x07\xac\xf0\x8c\x43\x10\x10\x6c\xa6\x12\xbc\x43\x7f\x0a\x2d\xe9\x81\xff\x3f\x01\xf8\xad\xb3\x54\x46\x0f\xa9\x9d\xf3\x41\x6d\x87\xd7\x6e\xaa\x4d\xae\xcc\x18\xc6\xee\x7b\x7d\x8b\xd3\x4e\xd5\xb1\x3d\xf6\xf4\x1d\x00\x00\xff\xff\x27\xc6\x8c\x66\x3f\x01\x00\x00")

func testAssetsAppIngressDeploymentYamlBytes() ([]byte, error) {
	return bindataRead(
		_testAssetsAppIngressDeploymentYaml,
		"test/assets/app-ingress/deployment.yaml",
	)
}

func testAssetsAppIngressDeploymentYaml() (*asset, error) {
	bytes, err := testAssetsAppIngressDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "test/assets/app-ingress/deployment.yaml", size: 319, mode: os.FileMode(420), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x3b, 0x30, 0x30, 0xdd, 0x18, 0x6f, 0x95, 0x83, 0x55, 0xff, 0x3b, 0x7, 0xfb, 0x69, 0x99, 0xd1, 0x98, 0xe7, 0x9, 0x38, 0x85, 0xea, 0x95, 0xf3, 0x4e, 0xb2, 0x28, 0x7e, 0x36, 0x71, 0x1b, 0x4f}}
	return a, nil
}

var _testAssetsAppIngressNamespaceYaml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x2c\xcb\x31\xae\x02\x31\x0c\x45\xd1\x3e\xab\x78\x9a\x7e\xe6\xeb\xb7\x59\x04\x25\xbd\x99\x79\x80\x45\x12\x47\xb6\x61\xfd\x08\x44\x7d\xef\x79\xe8\x38\x2a\x4e\xd2\x19\x53\x76\x16\x99\x7a\xa6\x87\xda\xa8\x78\xfd\x97\xce\x94\x43\x52\x6a\x01\x86\x74\x56\xec\xed\x19\x49\x5f\x75\xdc\x9c\x11\x6b\x32\xb2\x00\x4d\x2e\x6c\xf1\xd9\x80\x5f\xda\x6c\x72\xc4\x5d\xaf\xb9\xa9\xfd\xd9\xa4\x4b\x9a\x7f\x41\xc5\xb2\x94\x77\x00\x00\x00\xff\xff\x15\x0b\x51\x43\x7b\x00\x00\x00")

func testAssetsAppIngressNamespaceYamlBytes() ([]byte, error) {
	return bindataRead(
		_testAssetsAppIngressNamespaceYaml,
		"test/assets/app-ingress/namespace.yaml",
	)
}

func testAssetsAppIngressNamespaceYaml() (*asset, error) {
	bytes, err := testAssetsAppIngressNamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "test/assets/app-ingress/namespace.yaml", size: 123, mode: os.FileMode(420), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x22, 0x77, 0x8, 0x2, 0x27, 0xbc, 0x39, 0x12, 0xdf, 0x2e, 0x3c, 0x4e, 0x57, 0x45, 0x78, 0xd9, 0x3f, 0x97, 0xa0, 0x3, 0x84, 0x45, 0xc1, 0x74, 0x78, 0xa2, 0xe7, 0x9, 0x8d, 0x94, 0xad, 0x47}}
	return a, nil
}

var _testAssetsAppIngressRouteYaml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x4c\x8e\xb1\x8e\x83\x30\x0c\x86\xf7\x3c\x85\x5f\x80\x9c\x6e\xcd\x86\x10\xdb\xdd\xe9\x04\x6d\xd7\xca\x4a\x4c\x89\x0a\x89\x15\x1b\x9e\xbf\x4a\x61\xe8\xe8\xcf\xfa\x3f\x7d\xc8\xf1\x46\x45\x62\x4e\x0e\x4a\xde\x94\x6c\x66\x4a\x32\xc7\x49\x6d\xcc\x5f\xfb\xb7\x79\xc6\x14\x1c\x0c\xf5\x67\x56\x52\x0c\xa8\xe8\x0c\x40\xc2\x95\x1c\x04\x9a\x70\x5b\xf4\xbc\x85\xd1\x93\x03\xbf\x6c\xa2\x54\x9a\x98\x1e\x85\x44\x1a\x25\x51\x23\x4c\xbe\xee\xe6\x2c\xea\x00\x99\xed\x5f\xfb\xdb\x8f\xff\x6d\xd7\x5b\x64\x16\xdb\xfd\x5c\xc7\x4b\x3f\xdc\x2b\xb6\x81\xf6\xd3\xf2\x11\xe4\xf3\x6a\x00\x34\x57\x0d\xc0\x11\x36\x52\xd9\xa3\xa7\x37\x39\x92\x90\xd9\xbc\x02\x00\x00\xff\xff\x7f\xca\xa0\x49\xd7\x00\x00\x00")

func testAssetsAppIngressRouteYamlBytes() ([]byte, error) {
	return bindataRead(
		_testAssetsAppIngressRouteYaml,
		"test/assets/app-ingress/route.yaml",
	)
}

func testAssetsAppIngressRouteYaml() (*asset, error) {
	bytes, err := testAssetsAppIngressRouteYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "test/assets/app-ingress/route.yaml", size: 215, mode: os.FileMode(420), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x8d, 0x4b, 0xc1, 0x46, 0x37, 0x57, 0x5b, 0x41, 0xc, 0x5, 0x27, 0x67, 0x64, 0x8c, 0x39, 0x7, 0xee, 0xea, 0x28, 0x1a, 0x3f, 0x7, 0xba, 0x22, 0x73, 0x7, 0xf6, 0xf2, 0x8c, 0x94, 0xfc, 0x9f}}
	return a, nil
}

var _testAssetsAppIngressServiceYaml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x54\x8b\x41\xaa\xc3\x30\x0c\x05\xf7\x3e\x85\x2e\x10\xc8\xdf\x05\x6d\xff\x05\x02\x2d\xdd\x0b\xe7\x11\x4c\x1d\x5b\x48\x6a\xce\x5f\x1c\xb2\xe9\x6e\xa4\x79\xf3\x2e\x6d\x63\x7a\xc0\xce\x92\x91\x44\xcb\x0b\xe6\xa5\x37\xa6\xf3\x2f\x1d\x08\xd9\x24\x84\x13\x51\x93\x03\x4c\xa2\x7a\xb3\xab\x64\x30\xe5\xfa\xf1\x80\x4d\xa5\xed\x06\xf7\x29\xe0\x91\x5c\x91\x47\xe3\xa8\xc8\xd1\x6d\x30\x8d\x96\xe9\x67\x47\xa4\xdd\xc2\x87\x9e\x48\xad\x47\xcf\xbd\x32\x3d\xff\xd7\x2b\x18\x92\x69\x99\xaf\x23\xc4\x76\xc4\x7a\xbf\x96\x39\x7d\x03\x00\x00\xff\xff\xd9\x18\x76\x42\xba\x00\x00\x00")

func testAssetsAppIngressServiceYamlBytes() ([]byte, error) {
	return bindataRead(
		_testAssetsAppIngressServiceYaml,
		"test/assets/app-ingress/service.yaml",
	)
}

func testAssetsAppIngressServiceYaml() (*asset, error) {
	bytes, err := testAssetsAppIngressServiceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "test/assets/app-ingress/service.yaml", size: 186, mode: os.FileMode(420), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x16, 0x53, 0xe4, 0x77, 0x4a, 0xb0, 0x54, 0x79, 0xbb, 0x12, 0xf8, 0x69, 0xb8, 0x59, 0x90, 0x8a, 0x5a, 0x2c, 0x4, 0xb8, 0xac, 0x2c, 0xa8, 0x3, 0x84, 0x9c, 0xcc, 0x91, 0xe6, 0x4b, 0x91, 0x13}}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetString returns the asset contents as a string (instead of a []byte).
func AssetString(name string) (string, error) {
	data, err := Asset(name)
	return string(data), err
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// MustAssetString is like AssetString but panics when Asset would return an
// error. It simplifies safe initialization of global variables.
func MustAssetString(name string) string {
	return string(MustAsset(name))
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetDigest returns the digest of the file with the given name. It returns an
// error if the asset could not be found or the digest could not be loaded.
func AssetDigest(name string) ([sha256.Size]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s can't read by error: %v", name, err)
		}
		return a.digest, nil
	}
	return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s not found", name)
}

// Digests returns a map of all known files and their checksums.
func Digests() (map[string][sha256.Size]byte, error) {
	mp := make(map[string][sha256.Size]byte, len(_bindata))
	for name := range _bindata {
		a, err := _bindata[name]()
		if err != nil {
			return nil, err
		}
		mp[name] = a.digest
	}
	return mp, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"test/assets/app-ingress/deployment.yaml": testAssetsAppIngressDeploymentYaml,

	"test/assets/app-ingress/namespace.yaml": testAssetsAppIngressNamespaceYaml,

	"test/assets/app-ingress/route.yaml": testAssetsAppIngressRouteYaml,

	"test/assets/app-ingress/service.yaml": testAssetsAppIngressServiceYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"},
// AssetDir("data/img") would return []string{"a.png", "b.png"},
// AssetDir("foo.txt") and AssetDir("notexist") would return an error, and
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"test": {nil, map[string]*bintree{
		"assets": {nil, map[string]*bintree{
			"app-ingress": {nil, map[string]*bintree{
				"deployment.yaml": {testAssetsAppIngressDeploymentYaml, map[string]*bintree{}},
				"namespace.yaml":  {testAssetsAppIngressNamespaceYaml, map[string]*bintree{}},
				"route.yaml":      {testAssetsAppIngressRouteYaml, map[string]*bintree{}},
				"service.yaml":    {testAssetsAppIngressServiceYaml, map[string]*bintree{}},
			}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory.
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively.
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
