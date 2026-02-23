package pure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/warpstreamlabs/bento/public/service"
)

func testTemplateProc(confStr string) (service.Processor, error) {
	pConf, err := templateProcSpec().ParseYAML(confStr, nil)
	if err != nil {
		return nil, err
	}
	return newTemplateProcessor(pConf, service.MockResources())
}

func TestTemplateProcessor(t *testing.T) {
	tests := []struct {
		name          string
		template      string
		input         []byte
		metaKV        map[string]string
		expected      string
		expectedError bool
		errorValue    string
	}{
		{
			name:     "basic template",
			template: `template: "{{ .foo }} - {{ meta \"meta_foo\" }}"`,
			input:    []byte(`{"foo":"bar"}`),
			metaKV:   map[string]string{"meta_foo": "meta_bar"},
			expected: "bar - meta_bar",
		},
		{
			name:     "range template",
			template: `template: "{{ range .items }}{{ .name }}: {{ .value }}{{ end }}"`,
			input:    []byte(`{"items":[{"name":"foo","value":1},{"name":"bar","value":2}]}`),
			expected: "foo: 1bar: 2",
		},
		{
			name:     "meta access with values",
			template: `template: "{{ meta \"key1\" }} - {{ meta \"key2\" }}"`,
			input:    []byte(`{}`),
			metaKV:   map[string]string{"key1": "value1", "key2": "value2"},
			expected: "value1 - value2",
		},
		{
			name:     "meta access with nonexistent key",
			template: `template: "{{ meta \"nonexistent\" }}"`,
			input:    []byte(`{}`),
			expected: "<no value>",
		},
		{
			name:     "field access with nonexistent key",
			template: `template: "{{ .nonexistent }}"`,
			input:    []byte(`{}`),
			expected: "<no value>",
		},
		{
			name:          "invalid template syntax",
			template:      `template: "{{ invalid syntax"`,
			expectedError: true,
			errorValue:    "Failed to parse template",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proc, err := testTemplateProc(test.template)
			if test.expectedError {
				require.ErrorContains(t, err, test.errorValue)
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, proc.Close(context.Background())) })

			msg := service.NewMessage(test.input)
			for k, v := range test.metaKV {
				msg.MetaSetMut(k, v)
			}

			batch, err := proc.Process(t.Context(), msg)
			require.NoError(t, err)
			require.Len(t, batch, 1)

			result, err := batch[0].AsBytes()
			require.NoError(t, err)
			assert.Equal(t, test.expected, string(result))
		})
	}
}
