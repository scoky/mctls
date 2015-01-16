function [] = plotHandshake() 

% Common variables 
folder = '/home/varvello/WorkTelefonica/HTTP-2/results'; 
figFolder = './fig';
kind_line = ['m';'b';'g';'m';'b';'g';'m';'b';'g';'m';'o';':';'d';'+';'<';'s';'.';'-';'g';'p'];
line_style = ['-';';';':'];

% Close figures 
close all 

% Plotting protocol usage evolution over time
protocol = [
	'ssl'
	'spp'
	]; 
nProt = size(protocol, 1); 
handshakeTime = figure(); 
hold on 

% Load data to plot from files 
counter = 1;
for ii = 1 : nProt
	currProt = strtrim(protocol(ii, :)); 
	file = sprintf('res_%s', currProt); 
	data = dlmread(file); 
	h = errorbar(data(:, 2), data(:, 3)); 
	if (ii > 3) 
		set (h, 'color', kind_line(counter), 'LineWidth', 3, 'LineStyle', '--');
	else 
		set (h, 'color', kind_line(counter), 'LineWidth', 3);
	end
	if (ii == 1)
		leg = {sprintf('%s',currProt)};
	else
		leg = [leg, {sprintf('%s', currProt)}];
	end
	counter = counter + 1; 
end

% Add figure details 
xlabel('No. slices (#)');
ylabel('Handshake Duration (ms)');
legend(leg, 'Location', 'NorthEast');
grid on 
set(0,'defaultaxesfontsize',18);
%set(gca, 'YScale','log'); 
outFile = sprintf ('%s/handshake_time_proto.eps', figFolder); 
saveas (h, outFile, 'psc2');

