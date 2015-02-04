library(ggplot2)
library(extrafont)
library(xkcd)


# ratioxy <- 1

t <- read.table("timeFirstByte_slice_local_local.pdf.tsv", header=T, sep="\t")
t <- t[t$X <= 16, ]

#ratioxy <- (max(t$X) - min(t$X)) / (max(t$Y) - min(t$Y))
#ratioxy <- diff(range(t$X)) / diff(range(t$Y))
ratioxy <- 0.024
print(ratioxy)
#ratioxy <- 15 / abs(max(t$Y) - min(t$Y))

#ratioxy <- 5/8

mapping <- aes(
  x,  y,
  scale,
  ratioxy,
  angleofspine,
  anglerighthumerus,
  anglelefthumerus,
  anglerightradius,
  angleleftradius,
  anglerightleg,
  angleleftleg,
  angleofneck)

dataman <- data.frame(
  # x= c(7,12), y=c(450, 525),
  x= c(14.75,9.25), y=c(550, 450),
  scale = 16.25,
  ratioxy = ratioxy,
  angleofspine =  -pi/2,
  anglerighthumerus = c(-pi/6, -pi/6),
  anglelefthumerus = c(pi * 7/6 , -pi/2 - pi/6),
  anglerightradius = c(pi * 7/6, -pi/5),
  angleleftradius = c(pi * 5/6, -pi/5),
  angleleftleg = 3*pi/2  + pi / 12,
  anglerightleg = 3*pi/2  - pi / 12,
  angleofneck = c(pi * 4.2/3, runif(1, 3*pi/2-pi/10, 3*pi/2+pi/10))
  )



p <- ggplot(data=t)

pdf("xkcd-slides/time-to-first-byte-per-context-xkcd.pdf", 8, 5)
p +
  geom_point(mapping=aes(x=X, y=Y, color=protocol)) +
  geom_line(mapping=aes(x=X, y=Y, color=protocol)) +
  geom_errorbar(mapping=aes(x=X, ymin=Y-stddev, ymax=Y+stddev, color=protocol, width=0.2)) +
#  geom_smooth(mapping=aes(x=X, y=Y, color=protocol), se=FALSE) +
  theme_xkcd() +
  annotate("text", x=9.25, y=493, label="At 10 contexts, data\nfrom the middlebox\nexceeds 1 MSS", family="xkcd", size=3) +
  annotate("text", x=14.75, y=460, label="At 14 contexts, key\nmaterial from client\nand server\nexceed 1 MSS each", family="xkcd", size=3) +
  theme(legend.position="top") +
  # xlim(c(0, 16)) +
  xkcdaxis(range(t$X), range(t$Y)) +
  ylab("Time to First Byte in miliseconds") +
  xlab("Number of Contexts") +
  xkcdman(mapping, dataman)

dev.off()



t <- read.table("connections_slice_local_mbox_54-76-148-166.pdf.tsv", header=T, sep="\t")

ratioxy <- diff(range(t$X)) / diff(range(t$Y))

dataman <- data.frame(
  # x= c(7,12), y=c(450, 525),
  x= c(8.25), y=c(1100),
  scale = 150.25,
  ratioxy = ratioxy,
  angleofspine =  -pi/2,
  anglerighthumerus = c(-pi/6),
  anglelefthumerus = c(-pi/2 - pi/6),
  anglerightradius = c(-pi/5),
  angleleftradius = c(-pi/5),
  angleleftleg = 3*pi/2  + pi / 12,
  anglerightleg = 3*pi/2  - pi / 12,
  angleofneck = c(runif(1, 3*pi/2-pi/10, 3*pi/2+pi/10))
)

p <- ggplot(data=t)

pdf("xkcd-slides/connections-per-second-num-contexts-mbox-xkcd.pdf", 8, 5)
p +
  geom_point(mapping=aes(x=X, y=Y, color=protocol)) +
  geom_line(mapping=aes(x=X, y=Y, color=protocol)) +
  geom_errorbar(mapping=aes(x=X, ymin=Y-stddev, ymax=Y+stddev, color=protocol, width=0.2)) +
  #  geom_smooth(mapping=aes(x=X, y=Y, color=protocol), se=FALSE) +
  theme_xkcd() +
  annotate("text", x=8.25, y=1500, label="mcTLS actually improves middlebox performance!", family="xkcd", size=5) +
  theme(legend.position="top") +
  # xlim(c(0, 16)) +
  xkcdaxis(range(t$X), range(t$Y)) +
  ylab("Middlebox Connections per second") +
  xlab("Number of Contexts") +
  xkcdman(mapping, dataman)

dev.off()

t <- read.table("connections_slice_local_server_54-76-148-166.pdf.tsv", header=T, sep="\t")

ratioxy <- diff(range(t$X)) / diff(range(t$Y))

dataman <- data.frame(
  # x= c(7,12), y=c(450, 525),
  x= c(8.25), y=c(470),
  scale = 15.25,
  ratioxy = ratioxy,
  angleofspine =  -pi/2,
  anglerighthumerus = c(-pi/6),
  anglelefthumerus = c(-pi/2 - pi/6),
  anglerightradius = c(-pi/5),
  angleleftradius = c(-pi/5),
  angleleftleg = 3*pi/2  + pi / 12,
  anglerightleg = 3*pi/2  - pi / 12,
  angleofneck = c(runif(1, 3*pi/2-pi/10, 3*pi/2+pi/10))
)

p <- ggplot(data=t)

pdf("xkcd-slides/connections-per-second-num-contexts-server-xkcd.pdf", 8, 5)
p +
  geom_point(mapping=aes(x=X, y=Y, color=protocol)) +
  geom_line(mapping=aes(x=X, y=Y, color=protocol)) +
  geom_errorbar(mapping=aes(x=X, ymin=Y-stddev, ymax=Y+stddev, color=protocol, width=0.2)) +
  #  geom_smooth(mapping=aes(x=X, y=Y, color=protocol), se=FALSE) +
  theme_xkcd() +
  annotate("text", x=8.25, y=500, label="More contexts or middleboxes only degrades\nserver performance a little bit.", family="xkcd", size=5) +
  theme(legend.position="top") +
  # xlim(c(0, 16)) +
  xkcdaxis(range(t$X), range(t$Y)) +
  ylab("Server Connections per second") +
  xlab("Number of Contexts") +
  xkcdman(mapping, dataman)

dev.off()
