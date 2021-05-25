package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/DataDog/zstd"
	_ "github.com/mattn/go-sqlite3" // Imports sqlite db drivers
	"github.com/valyala/gozstd"

	"github.com/pastelnetwork/gonode/common/errors"
	pruntime "github.com/pastelnetwork/gonode/common/runtime"
)

const dupeDetectionImageFingerprintDatabaseFilePath = "dupe_detection_image_fingerprint_database.sqlite"

func loadFingerprintsFromDBFile() ([][]byte, error) {
	defer pruntime.PrintExecutionTime(time.Now())

	db, err := sql.Open("sqlite3", dupeDetectionImageFingerprintDatabaseFilePath)
	if err != nil {
		return nil, errors.New(err)
	}
	defer db.Close()

	var arrayOfCombinedImageFingerprintRows [][]byte

	selectQuery := `
			SELECT model_1_image_fingerprint_vector, model_2_image_fingerprint_vector, model_3_image_fingerprint_vector, model_4_image_fingerprint_vector, model_5_image_fingerprint_vector,
				model_6_image_fingerprint_vector, model_7_image_fingerprint_vector FROM image_hash_to_image_fingerprint_table ORDER BY datetime_fingerprint_added_to_database DESC
		`
	rows, err := db.Query(selectQuery)
	if err != nil {
		return nil, errors.New(err)
	}
	defer rows.Close()

	for rows.Next() {
		var model1ImageFingerprintVector, model2ImageFingerprintVector, model3ImageFingerprintVector, model4ImageFingerprintVector, model5ImageFingerprintVector, model6ImageFingerprintVector, model7ImageFingerprintVector []byte
		err = rows.Scan(&model1ImageFingerprintVector, &model2ImageFingerprintVector, &model3ImageFingerprintVector, &model4ImageFingerprintVector, &model5ImageFingerprintVector, &model6ImageFingerprintVector, &model7ImageFingerprintVector)
		if err != nil {
			return nil, errors.New(err)
		}
		combinedImageFingerprintVector := append(append(append(append(append(append(model1ImageFingerprintVector, model2ImageFingerprintVector[:]...), model3ImageFingerprintVector[:]...), model4ImageFingerprintVector[:]...), model5ImageFingerprintVector[:]...), model6ImageFingerprintVector[:]...), model7ImageFingerprintVector[:]...)

		arrayOfCombinedImageFingerprintRows = append(arrayOfCombinedImageFingerprintRows, combinedImageFingerprintVector)
	}

	return arrayOfCombinedImageFingerprintRows, nil
}

func zstdCompressLevel22(data []byte) error {
	output, err := zstd.CompressLevel(nil, data, 22)
	if err != nil {
		return errors.New(err)
	}

	fmt.Printf("\nCompression ratio of zstd.CompressLevel 22 without dicitionary: %.2f%%", float32(len(output))/float32(len(data))*100.0)
	return nil
}

func zstdWriterLevel22Dict(data, dict []byte) error {
	var w bytes.Buffer
	writer := zstd.NewWriterLevelDict(&w, 22, dict)
	_, err := writer.Write(data)
	if err != nil {
		return errors.New(err)
	}
	err = writer.Close()
	if err != nil {
		return errors.New(err)
	}
	out := w.Bytes()
	fmt.Printf("\nCompression ratio of zstdWriterLevel22Dict with dictionary: %.2f%%", float32(len(out))/float32(len(data))*100.0)
	return nil
}

func zstdWriterLevel22(data []byte) error {
	var w bytes.Buffer
	writer := zstd.NewWriterLevel(&w, 22)
	_, err := writer.Write(data)
	if err != nil {
		return errors.New(err)
	}
	err = writer.Close()
	if err != nil {
		return errors.New(err)
	}
	out := w.Bytes()
	fmt.Printf("\nCompression ratio of zstdWriterLevel22 without dictionary: %.2f%%", float32(len(out))/float32(len(data))*100.0)
	return nil
}

func buildDictionary(dictionaryFilePath string) error {
	defer pruntime.PrintExecutionTime(time.Now())

	samples, err := loadFingerprintsFromDBFile()
	if err != nil {
		return errors.New(err)
	}

	fmt.Printf("\nCount of loaded fingerprints to build the dictionary %v", len(samples))

	// Build a dictionary with the specified size of 1024Kb.
	dictionary := gozstd.BuildDict(samples, 100*1024*1024)
	err = os.WriteFile("dictionary", dictionary, 0644)
	if err != nil {
		return errors.New(err)
	}

	for i := 0; i < 10; i++ {
		fmt.Printf("\n----Compressing fingerprint #%v", i)
		err = zstdCompressLevel22(samples[i])
		if err != nil {
			return errors.New(err)
		}

		err = zstdWriterLevel22(samples[i])
		if err != nil {
			return errors.New(err)
		}

		err = zstdWriterLevel22Dict(samples[i], dictionary)
		if err != nil {
			return errors.New(err)
		}
	}

	return nil
}

func main() {
	err := buildDictionary("dictionary")
	if err != nil {
		if err, isCommonError := err.(*errors.Error); isCommonError {
			fmt.Println(errors.ErrorStack(err))
		}
		panic(err)
	}
}
