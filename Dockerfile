# Dockerfile for building the containerized makecerts
# golang:1.21 as of 2023-09-29
FROM golang@sha256:19600fdcae402165dcdab18cb9649540bde6be7274dedb5d205b2f84029fe909 AS build

MAINTAINER William Rouesnel <wrouesnel@wrouesnel.com>
EXPOSE 9115

COPY ./ /workdir/
WORKDIR /workdir

RUN go run mage.go binary

FROM scratch

MAINTAINER Will Rouesnel <wrouesnel@wrouesnel.com>

ENV PATH=/bin
COPY --from=build /workdir/makecerts /bin/makecerts

ENTRYPOINT ["/bin/makecerts"]

