docker:
	docker build -t ebpf-generate -f Dockerfile .

generate:
	 docker run -i -t -v $$(pwd)/../../../:/target ebpf-generate
