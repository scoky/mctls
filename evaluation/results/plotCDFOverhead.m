% function to plot several statistics for the Sigcomm paper 
% opt - graph type 
% remote   - local or remote experiment
% parallel - if = 1 it refers to experiment ran on multiple machines at the same time
% role     - required by option 7 to indicate whether we wannt plot for "client", "server" or "mbox"

function [] = plotCDFOverhead(res)

MAC 		= 9/5
HANDSHAKE	= 8/5
PADDING 	= 6/5
HEADER		= 7/5

% Common variables 
folder = sprintf ('/home/varvello/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/evaluation/%s', res);  
figFolder = './fig/matlab';
kind_line = ['m';'b';'g';'m';'b';'g';'m';'b';'g';'m';'o';':';'d';'+';'<';'s';'.';'-';'g';'p'];
line_style = ['-';';';':'];

% Protocol  and protocol labels 
protocol = [
	'spp    '
	%'spp_mod'
	'fwd    '
	'ssl    '
	%'pln    '
	]; 
nProt = size(protocol, 1); 

protoLabel = [
	'SPP             '
	%'SPP-no-NAGEL    '
	'TLS (forwarding)'
	'TLS (splitting) '
	%'PLN             '
	]; 

ovLabel = [
	'PADDING  '
	'HEADER   '
	'HANDSHAKE'
	'MAC      '
	]; 

%FIXME
%res_ssl_four-slices_byteOverhead_browser
suffix = 'four-slices_byteOverhead_browser'

overheadTypes = 4	
appData = 5
counter = 1

% create Figure handlers
for jj = 1 : overheadTypes
	fig(jj) = figure(); 
end

% iterate over protocols 
for ii = 1 : nProt
	currProt = strtrim(protocol(ii, :)) 
	currProtLabel = strtrim(protoLabel(ii, :)); 
	%FIXME
	file = sprintf('%s/res_%s_%s', folder, currProt, suffix) 
	if exist(file, 'file') ~= 2
		continue
	end
	data = dlmread(file);
	
	for jj = 1 : overheadTypes
		figure(fig(jj)); 
		h = cdfplot(data(:, (appData + jj))./data(:, appData)); 
		hold on; 
		if (ii > 3) 
			set (h, 'color', kind_line(counter), 'LineWidth', 3, 'LineStyle', '--');
		else 
			set (h, 'color', kind_line(counter), 'LineWidth', 3);
		end
	end
	if (counter == 1)
		leg = {sprintf('%s',currProtLabel)};
	else
		leg = [leg, {sprintf('%s', currProtLabel)}];
	end
	counter = counter + 1; 
end

for jj = 1 : overheadTypes
	figure(fig(jj)); 
	xlabel('% of App Data Size');
	ylabel('CDF (0-1)');
	legend(leg, 'Location', 'SouthEast');
	grid on 
	set(0,'defaultaxesfontsize',18);
	set(gca, 'XScale','log');
	overheadLabel = strtrim(ovLabel(jj, :)); 
	t = sprintf('%s', overheadLabel); 
	title(t);
	outFile = sprintf ('%s/overhead_%s.eps', figFolder, overheadLabel); 
	saveas (fig(jj), outFile, 'psc2');
end
