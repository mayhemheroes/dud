package fuzzdud

import (
    "strconv"
    fuzz "github.com/AdaLogics/go-fuzz-headers"

    "github.com/kevin-hanselman/dud/src/artifact"
    "github.com/kevin-hanselman/dud/src/cache"
    "github.com/kevin-hanselman/dud/src/fsutil"
    "github.com/kevin-hanselman/dud/src/stage"
)

func mayhemit(bytes []byte) int {

    var num int
    if len(bytes) > 2 {
        num, _ = strconv.Atoi(string(bytes[0]))
        bytes = bytes[1:]
        fuzzConsumer := fuzz.NewConsumer(bytes)
        
        switch num {

            case 0:
                testDir, _ := fuzzConsumer.GetString()
                cache.NewLocalCache(testDir)
                return 0

            case 1:
                testPath, _ := fuzzConsumer.GetString()
                testCache := &cache.LocalCache{}
                err := fuzzConsumer.GenerateStruct(testCache)
                if err != nil {
                    return 0
                }

                testCache.PathForChecksum(testPath)
                return 0

            case 2:
                var testMap map[string]*artifact.Artifact
                testCache := &cache.LocalCache{}
                testDst, _ := fuzzConsumer.GetString()
                err := fuzzConsumer.FuzzMap(&testMap)
                if err != nil {
                    return 0
                }

                err = fuzzConsumer.GenerateStruct(testCache)
                if err != nil {
                    return 0
                }

                testCache.Push(testDst, testMap)
                return 0

            case 3:
                testBool, _ := fuzzConsumer.GetBool()
                testDir, _ := fuzzConsumer.GetString()
                testCache := &cache.LocalCache{}
                testArtifact := artifact.Artifact{}
                err := fuzzConsumer.GenerateStruct(testCache)
                if err != nil {
                    return 0
                }

                err = fuzzConsumer.GenerateStruct(&testArtifact)
                if err != nil {
                    return 0
                }

                testCache.Status(testDir, testArtifact, testBool)
                return 0

            case 4:
                testPath, _ := fuzzConsumer.GetString()
                testBool, _ := fuzzConsumer.GetBool()

                fsutil.Exists(testPath, testBool)
                return 0

            case 5:
                testPath, _ := fuzzConsumer.GetString()

                fsutil.IsLink(testPath)
                return 0

            case 6:
                testPath, _ := fuzzConsumer.GetString()

                fsutil.IsRegularFile(testPath)
                return 0

            case 7:
                testPath, _ := fuzzConsumer.GetString()

                fsutil.FileStatusFromPath(testPath)
                return 0

            case 8:
                testPathA, _ := fuzzConsumer.GetString()
                testPathB, _ := fuzzConsumer.GetString()

                fsutil.SameContents(testPathA, testPathB)
                return 0

            case 9:
                testPath, _ := fuzzConsumer.GetString()

                stage.FromFile(testPath)
                return 0

            case 10:
                testPath, _ := fuzzConsumer.GetString()
                testStage := stage.Stage{}
                err := fuzzConsumer.GenerateStruct(&testStage)
                if err != nil {
                    return 0
                }

                testStage.Validate(testPath)
                return 0

            default:
                testArtifact := &artifact.Artifact{}
                testBytes, _ := fuzzConsumer.GetBytes()
                
                err := fuzzConsumer.GenerateStruct(testArtifact)
                if err != nil {
                    return 0
                }

                testArtifact.UnmarshalJSON(testBytes)
                return 0
        }
    }
    return 0
}

func Fuzz(data []byte) int {
    _ = mayhemit(data)
    return 0
}